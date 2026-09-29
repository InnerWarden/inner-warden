import {
  ACTIVITY_TOUR_STEP_KEY,
  COMMUNITY_TOUR_STEPS,
  COMMUNITY_UPGRADE_STEP_KEY,
  TOUR_FINISH_STEP_KEY,
  TOUR_WELCOME_STEP_KEY,
  type TourStep,
} from "../components/ProductTour";

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
    title: "Three questions",
    body: "What your AI agent did, what people asked it, and what Community does not watch. Each card opens what is behind it.",
    route: "overview",
    selectors: ['[data-tour="overview-lanes"]', 'section[aria-labelledby="lanes-title"]'],
  },
  {
    key: ACTIVITY_TOUR_STEP_KEY,
    title: "Cases",
    body: "Every command the guard flagged, one case each, with what you can do about it.",
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
    title: "Going further: Active Defence",
    body: "Community screens what your agents try to run. Active Defence is the paid edition for Linux servers: it adds the kernel Execution Gate, Secret Read Guard, DNS Guard, the host sensor and automatic response. The Protection page lists them.",
    route: "posture",
    selectors: ['[data-tour="upgrade"]'],
  },
  shared(TOUR_FINISH_STEP_KEY),
];

/** The steps for a machine, with the pitch dropped where Active Defence is installed. */
export function communityShellTourSteps(activeDefenceInstalled: boolean): readonly TourStep[] {
  if (!activeDefenceInstalled) return COMMUNITY_SHELL_TOUR_STEPS;
  return COMMUNITY_SHELL_TOUR_STEPS.filter((step) => step.key !== COMMUNITY_UPGRADE_STEP_KEY);
}
