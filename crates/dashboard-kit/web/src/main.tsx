import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import { App } from "./App";
import { fetchMeta } from "./api";
import {
  COMMUNITY_TOUR_STORAGE_KEY,
  TourLauncher,
  communityTourSteps,
} from "./components/ProductTour";

// The shell plus the guided tour layer. The tour opens itself once, on a first
// visit, and stays reachable afterwards from the Tour button in the header; its
// step table lives in `components/ProductTour.tsx` so a test can import it.

/**
 * The tour renders beside the shell rather than inside it, so it asks the
 * server itself for the one fact that changes its table: whether this host
 * already runs Active Defence. On a host that does, the upgrade step would
 * otherwise read the pitch out to somebody who already owns the product.
 *
 * Until the answer arrives, and if it never does, the full table stands. An
 * unreachable endpoint is not evidence of an installation, and offering a host
 * something it may well want is the recoverable direction to be wrong in.
 */
function CommunityTour() {
  const [activeDefenceInstalled, setActiveDefenceInstalled] = useState(false);

  useEffect(() => {
    let active = true;
    fetchMeta()
      .then((meta) => {
        if (active) setActiveDefenceInstalled(meta.active_defence_installed ?? false);
      })
      .catch(() => {
        // Leave the full table in place.
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <TourLauncher
      steps={communityTourSteps(activeDefenceInstalled)}
      storageKey={COMMUNITY_TOUR_STORAGE_KEY}
    />
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
    <CommunityTour />
  </StrictMode>,
);
