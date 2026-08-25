import { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import { App } from "./App";
import type { DashboardMeta } from "./api";
import {
  COMMUNITY_TOUR_STORAGE_KEY,
  TourLauncher,
  communityTourSteps,
} from "./components/ProductTour";

// The shell plus the guided tour layer. The tour opens itself once, on a first
// visit, and stays reachable afterwards from the Tour button in the header; its
// step table lives in `components/ProductTour.tsx` so a test can import it.

/**
 * The shell and the tour, with the tour's step table decided by a fact the
 * shell has already read.
 *
 * The tour needs to know whether this host runs Active Defence: on one that
 * does, its upgrade step would read the pitch out to somebody who already owns
 * the product. It takes that answer from `onMeta` rather than fetching it,
 * because `guard/meta` is POLLED and a second reader of the same endpoint
 * desynchronises anything counting the sequence. The community posture journey
 * fails the SECOND reading on purpose, to prove a stale claim gets withdrawn; a
 * duplicate fetch answered that 503 into the wrong caller, and the claim stood.
 *
 * Until a reading arrives, and if none ever does, the full table stands. An
 * unanswered endpoint is not evidence of an installation, and offering a host
 * something it may well want is the recoverable direction to be wrong in.
 */
function Shell() {
  const [activeDefenceInstalled, setActiveDefenceInstalled] = useState(false);

  return (
    <>
      <App
        onMeta={(meta: DashboardMeta) =>
          setActiveDefenceInstalled(meta.active_defence_installed ?? false)
        }
      />
      <TourLauncher
        steps={communityTourSteps(activeDefenceInstalled)}
        storageKey={COMMUNITY_TOUR_STORAGE_KEY}
      />
    </>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Shell />
  </StrictMode>,
);
