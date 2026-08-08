import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import { App } from "./App";
import {
  COMMUNITY_TOUR_STEPS,
  COMMUNITY_TOUR_STORAGE_KEY,
  TourLauncher,
} from "./components/ProductTour";

// The shell plus the guided tour layer. The tour opens itself once, on a first
// visit, and stays reachable afterwards from the Tour button in the header; its
// step table lives in `components/ProductTour.tsx` so a test can import it.

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
    <TourLauncher steps={COMMUNITY_TOUR_STEPS} storageKey={COMMUNITY_TOUR_STORAGE_KEY} />
  </StrictMode>,
);
