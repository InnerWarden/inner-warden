import { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import { App } from "./App";
import type { DashboardMeta } from "./api";
import { COMMUNITY_TOUR_STORAGE_KEY, TourLauncher } from "./components/ProductTour";
import { COMMUNITY_SHELL } from "./community/shell";
import { communityShellTourSteps } from "./community/tour";

// The Community entry point: the shell, the Community pages, and the guided
// tour layer. It is the ONLY file outside `src/community/` that imports from
// it (a unit test walks every file to hold that), and the paid bundle overlays
// its own entry point, so no Community page reaches the paid JavaScript.
//
// The tour opens itself once, on a first visit, and stays reachable
// afterwards from the Tour button in the header.

/**
 * The shell and the tour, with the tour's step table decided by a fact the
 * shell has already read.
 *
 * The tour needs to know whether this host runs Active Defence: on one that
 * does, its upgrade step would read the pitch out to somebody who already owns
 * the product. It takes that answer from `onMeta` rather than fetching it,
 * because `guard/meta` is POLLED and a second reader of the same endpoint
 * desynchronises anything counting the sequence.
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
        communityScreens={COMMUNITY_SHELL}
        onMeta={(meta: DashboardMeta) =>
          setActiveDefenceInstalled(meta.active_defence_installed ?? false)
        }
      />
      <TourLauncher
        steps={communityShellTourSteps(activeDefenceInstalled)}
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
