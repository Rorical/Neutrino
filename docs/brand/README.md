# Neutrino brand assets

## Concept

A neutrino crosses matter without interacting. The mark is a ring, the chain's
consensus boundary, crossed by a straight trajectory that exits through a gap and
continues as a single bright particle. It reads as "passes straight through": a
constant-size proof that carries a whole history without re-executing it.

The trajectory runs from violet (the proof system) to cyan (the particle). The ring
stays neutral so the mark survives in one colour.

## Files

| File | Use |
| --- | --- |
| `neutrino-icon.svg` | Icon on dark backgrounds, transparent |
| `neutrino-icon-light.svg` | Icon on light backgrounds, transparent |
| `neutrino-icon-app.svg` | App or avatar icon with rounded dark tile |
| `neutrino-icon-mono.svg` | Single colour via `currentColor` (favicons, terminals, embossing) |
| `neutrino-logo-dark.svg` / `-light.svg` | Horizontal lockup with wordmark |
| `png/` | Rendered icons at 1024, 512, 256, 64, 32, 16 and both lockups |
| `favicon.ico` | 16, 32 and 64 pixel tiles |
| `fonts/` | Space Grotesk SemiBold static instance and its OFL licence |

## Typography

The wordmark is **Space Grotesk SemiBold** (SIL Open Font License), chosen over
Inter, Sora, Manrope, Outfit and IBM Plex Mono for its technical, slightly
scientific letterforms and the open counters that survive small sizes. In the
lockup SVGs the wordmark is converted to outlines, so no font needs to be
installed to render them identically. The static instance and its licence live in
`fonts/`.

Pairings for product and documentation surfaces:

| Role | Face |
| --- | --- |
| Wordmark, headlines | Space Grotesk SemiBold, tracking -1 |
| UI and body text | Inter |
| Code, hashes, addresses | IBM Plex Mono |

Set "Neutrino" in sentence case. Never letter-space the wordmark beyond the
outlined lockup or set it in all caps.

## Colour

| Role | Hex |
| --- | --- |
| Ink (dark background, light-mode ring and text) | `#0B1020` |
| Ice (dark-mode ring and text) | `#E8F0FF` |
| Particle (cyan) | `#4FE3FF` |
| Proof (violet) | `#7C5CFF` |

## Construction

256-unit grid. Ring centre (128, 128), radius 84, stroke 12, 28-degree gap centred
at 135 degrees. Trajectory from (212, 44) to (74, 182), stroke 12, round caps.
Particle at (50, 206), radius 11, halo radius 22 at 22 percent opacity.

## Clear space and minimum size

Keep clear space of at least the ring stroke width times four around the mark.
The icon stays legible at 16 pixels; below 32 pixels drop the halo (the mono file
already does).

## Do not

- Rotate the trajectory or move the gap; the exit angle is the mark.
- Fill the ring or add a second particle.
- Recolour the ring; only the trajectory and particle carry colour.
