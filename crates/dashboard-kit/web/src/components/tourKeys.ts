/**
 * The tour's step keys a screen can name, and the attribute it names them
 * in, kept apart from the tour engine so a screen can say what it does not
 * render without pulling the overlay code into its own module.
 */

/** The step that points at the Overview's agent panel. */
export const OVERVIEW_AGENTS_TOUR_STEP_KEY = "overview-agents";

/** The step that points at the Overview's sensor panel. */
export const OVERVIEW_SENSOR_TOUR_STEP_KEY = "overview-sensor";

/**
 * The attribute a screen puts in its markup to say which tour steps point at
 * something it does not render in the view it is showing, by step key,
 * space-separated: `data-tour-absent="overview-agents overview-sensor"`.
 */
export const TOUR_ABSENT_ATTRIBUTE = "data-tour-absent";
