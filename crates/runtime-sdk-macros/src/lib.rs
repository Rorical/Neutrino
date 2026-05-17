//! Procedural macros for runtime authors targeting the Neutrino host ABI.
//!
//! The crate exists to keep proc-macro plumbing (`syn`, `quote`, host
//! target) out of the `no_std`, `riscv32im` SDK. Runtime authors depend on
//! `neutrino-runtime-sdk` and the macros are re-exported from there so
//! they only need a single dependency at the call site.

#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Error, ItemFn, ReturnType, parse_macro_input, spanned::Spanned};

/// Marks a function as the runtime's `execute_block` entrypoint.
///
/// The macro keeps the user function intact and additionally emits a
/// `#[unsafe(no_mangle)] pub unsafe extern "C" fn _neutrino_main()`
/// wrapper that the SDK's `_start` shim calls. The wrapper invokes the
/// user function and then `abort(0)` to terminate the VM cleanly so
/// the host observes a successful block.
///
/// Constraints (M2):
///
/// - The annotated function must take no arguments.
/// - The annotated function must return `()` (the unit type).
///
/// Future SDKs may relax both; for now the runtime author calls
/// `host_input`/`host_output` directly when richer plumbing is needed.
///
/// # Examples
///
/// ```ignore
/// use neutrino_runtime_sdk::entrypoint;
///
/// #[entrypoint]
/// fn execute_block() {
///     // ...
/// }
/// ```
#[proc_macro_attribute]
pub fn entrypoint(args: TokenStream, input: TokenStream) -> TokenStream {
    if !args.is_empty() {
        return Error::new_spanned(
            TokenStream2::from(args),
            "#[entrypoint] does not currently accept attribute arguments",
        )
        .to_compile_error()
        .into();
    }

    let user_fn = parse_macro_input!(input as ItemFn);

    if let Err(err) = validate_entrypoint(&user_fn) {
        return err.to_compile_error().into();
    }

    let user_name = &user_fn.sig.ident;
    let expanded = quote! {
        #user_fn

        #[cfg(target_arch = "riscv32")]
        #[unsafe(no_mangle)]
        #[allow(unsafe_code)]
        #[doc(hidden)]
        pub unsafe extern "C" fn _neutrino_main() {
            #user_name();
            ::neutrino_runtime_sdk::abort(0)
        }
    };

    expanded.into()
}

/// Marks a function as the runtime's single-transaction validation entrypoint.
///
/// The macro keeps the user function intact and additionally emits a
/// `#[unsafe(no_mangle)] pub unsafe extern "C" fn _neutrino_validate_tx()`
/// wrapper. The host can jump directly to that symbol to validate one raw
/// transaction against a supplied state root without applying a block.
///
/// Constraints match [`entrypoint`]: the annotated function must take no
/// arguments, return `()`, be non-`async`, non-`unsafe`, and non-generic.
#[proc_macro_attribute]
pub fn tx_validation_entrypoint(args: TokenStream, input: TokenStream) -> TokenStream {
    if !args.is_empty() {
        return Error::new_spanned(
            TokenStream2::from(args),
            "#[tx_validation_entrypoint] does not accept attribute arguments",
        )
        .to_compile_error()
        .into();
    }

    let user_fn = parse_macro_input!(input as ItemFn);

    if let Err(err) = validate_entrypoint(&user_fn) {
        return err.to_compile_error().into();
    }

    let user_name = &user_fn.sig.ident;
    let expanded = quote! {
        #user_fn

        #[cfg(target_arch = "riscv32")]
        #[unsafe(no_mangle)]
        #[unsafe(link_section = ".text.neutrino_entry")]
        #[allow(unsafe_code)]
        #[doc(hidden)]
        pub unsafe extern "C" fn _neutrino_validate_tx() {
            #user_name();
            ::neutrino_runtime_sdk::abort(0)
        }
    };

    expanded.into()
}

/// Marks a function as the runtime's read-only query entrypoint.
///
/// The macro keeps the user function intact and additionally emits a
/// `#[unsafe(no_mangle)] pub unsafe extern "C" fn _neutrino_query()`
/// wrapper. The host invokes that symbol with a borsh-encoded
/// `QueryRequest` in `host_input` and expects a borsh-encoded
/// `QueryResponse` written via `host_output`. State writes and deletes
/// are refused by the host with `Status::PermissionDenied`; the state
/// overlay is discarded after the call regardless.
///
/// The wrapped function decodes the request, dispatches by method
/// name, and writes the response — typically via
/// [`neutrino_runtime_sdk::query_dispatch`] which handles the borsh
/// envelope on the runtime author's behalf.
///
/// Constraints match [`entrypoint`]: the annotated function must take
/// no arguments, return `()`, be non-`async`, non-`unsafe`, and
/// non-generic.
#[proc_macro_attribute]
pub fn query_entrypoint(args: TokenStream, input: TokenStream) -> TokenStream {
    if !args.is_empty() {
        return Error::new_spanned(
            TokenStream2::from(args),
            "#[query_entrypoint] does not accept attribute arguments",
        )
        .to_compile_error()
        .into();
    }

    let user_fn = parse_macro_input!(input as ItemFn);

    if let Err(err) = validate_entrypoint(&user_fn) {
        return err.to_compile_error().into();
    }

    let user_name = &user_fn.sig.ident;
    let expanded = quote! {
        #user_fn

        #[cfg(target_arch = "riscv32")]
        #[unsafe(no_mangle)]
        #[unsafe(link_section = ".text.neutrino_entry")]
        #[allow(unsafe_code)]
        #[doc(hidden)]
        pub unsafe extern "C" fn _neutrino_query() {
            #user_name();
            ::neutrino_runtime_sdk::abort(0)
        }
    };

    expanded.into()
}

pub(crate) fn validate_entrypoint(item: &ItemFn) -> Result<(), Error> {
    if !item.sig.inputs.is_empty() {
        return Err(Error::new(
            item.sig.inputs.span(),
            "#[entrypoint] function must take no arguments",
        ));
    }

    if let ReturnType::Type(_, ty) = &item.sig.output {
        // Unit return is encoded as `-> ()`; reject anything else explicitly.
        if !matches!(ty.as_ref(), syn::Type::Tuple(t) if t.elems.is_empty()) {
            return Err(Error::new(
                ty.span(),
                "#[entrypoint] function must return `()`",
            ));
        }
    }

    if item.sig.asyncness.is_some() {
        return Err(Error::new(
            item.sig.asyncness.span(),
            "#[entrypoint] function must not be async",
        ));
    }

    if item.sig.unsafety.is_some() {
        return Err(Error::new(
            item.sig.unsafety.span(),
            "#[entrypoint] function must not be marked unsafe",
        ));
    }

    if !item.sig.generics.params.is_empty() {
        return Err(Error::new(
            item.sig.generics.span(),
            "#[entrypoint] function must not be generic",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn accepts_simple_unit_function() {
        let item: ItemFn = parse_quote! {
            fn execute_block() {
                let _x = 1;
            }
        };
        assert!(validate_entrypoint(&item).is_ok());
    }

    #[test]
    fn accepts_pub_unit_function() {
        let item: ItemFn = parse_quote! {
            pub fn execute_block() {}
        };
        assert!(validate_entrypoint(&item).is_ok());
    }

    #[test]
    fn accepts_explicit_unit_return() {
        let item: ItemFn = parse_quote! {
            fn execute_block() -> () {}
        };
        assert!(validate_entrypoint(&item).is_ok());
    }

    #[test]
    fn rejects_function_with_arguments() {
        let item: ItemFn = parse_quote! {
            fn execute_block(input: u32) {}
        };
        assert!(validate_entrypoint(&item).is_err());
    }

    #[test]
    fn rejects_function_with_non_unit_return() {
        let item: ItemFn = parse_quote! {
            fn execute_block() -> u32 { 0 }
        };
        assert!(validate_entrypoint(&item).is_err());
    }

    #[test]
    fn rejects_async_function() {
        let item: ItemFn = parse_quote! {
            async fn execute_block() {}
        };
        assert!(validate_entrypoint(&item).is_err());
    }

    #[test]
    fn rejects_unsafe_function() {
        let item: ItemFn = parse_quote! {
            unsafe fn execute_block() {}
        };
        assert!(validate_entrypoint(&item).is_err());
    }

    #[test]
    fn rejects_generic_function() {
        let item: ItemFn = parse_quote! {
            fn execute_block<T>() {}
        };
        assert!(validate_entrypoint(&item).is_err());
    }
}
