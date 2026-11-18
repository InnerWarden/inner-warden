import {
  ACTIVITY_TOUR_STEP_KEY,
  COMMUNITY_TOUR_STEPS,
  COMMUNITY_UPGRADE_STEP_KEY,
  TOUR_FINISH_STEP_KEY,
  TOUR_WELCOME_STEP_KEY,
  type TourStep,
} from "../components/ProductTour";
import { TOUR_UPGRADE_LINE } from "./offers";

/**
 * The Community shell's tour: the shared opening and closing steps, and one
 * step per Community screen.
 *
 * `COMMUNITY_TOUR_STEPS` in the kit stays the table the paid bundle composes
 * its own tour from, unchanged, so nothing here can add a step to the paid
 * tour. Every step below points at an anchor a Community page draws.
 */
function shared(key: string): TourStep {
  const step = COMMUNITY_TOUR_STEPS.find((candidate) => candidate.key === key);
  if (step === undefined) throw new Error(`the shared tour has no ${key} step`);
  return step;
}

export const COMMUNITY_SHELL_TOUR_STEPS: readonly TourStep[] = [
  shared(TOUR_WELCOME_STEP_KEY),
  shared("nav"),
  {
    key: "community-lanes",
    title: "Your agents at a glance",
    body: "Whether your AI agents are connected and in which mode, what was refused or would have been, and the one next step.",
    route: "overview",
    selectors: ['[data-tour="overview-verdict"]', '[data-tour="overview-lanes"]'],
  },
  {
    key: ACTIVITY_TOUR_STEP_KEY,
    title: "Decisions",
    body: "Every command or tool call the guard flagged, with what you can do about it.",
    route: "activity",
    selectors: ['[data-tour="activity"]'],
  },
  {
    key: "community-protection",
    title: "What Community covers",
    body: "Each control on this machine, the mode it is in, and the one command that changes it.",
    route: "posture",
    selectors: ['[data-tour="community-protection"]'],
  },
  {
    key: COMMUNITY_UPGRADE_STEP_KEY,
    title: "Going further",
    body: TOUR_UPGRADE_LINE,
    route: "posture",
    selectors: ['[data-tour="upgrade"]'],
  },
  shared(TOUR_FINISH_STEP_KEY),
];

/** The steps for a machine, with the upgrade step dropped where the paid edition is installed. */
export function communityShellTourSteps(activeDefenceInstalled: boolean): readonly TourStep[] {
  if (!activeDefenceInstalled) return COMMUNITY_SHELL_TOUR_STEPS;
  return COMMUNITY_SHELL_TOUR_STEPS.filter((step) => step.key !== COMMUNITY_UPGRADE_STEP_KEY);
}
