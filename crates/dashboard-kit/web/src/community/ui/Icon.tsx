import type { ReactNode } from "react";
import { HATCH_PATTERN } from "../outcomeStyle";

/**
 * Community's sixteen icons, drawn by hand on a 16 px grid: a 1.5 px stroke
 * in the current colour, hidden from screen readers. An icon never carries a
 * meaning alone; the words beside it do.
 */
export const ICON_NAMES = [
  "shield",
  "half-shield",
  "eye",
  "triangle",
  "dashed-circle",
  "hollow-circle",
  "slashed-circle",
  "globe",
  "octagon",
  "diamond",
  "circle",
  "square",
  "copy",
  "arrow-right",
  "terminal",
  "plug",
] as const;
export type IconName = (typeof ICON_NAMES)[number];

const SHIELD = "M8 1.75 2.75 3.6v3.9c0 3.05 2.2 5.55 5.25 6.75 3.05-1.2 5.25-3.7 5.25-6.75V3.6L8 1.75Z";

const PATHS: Record<IconName, ReactNode> = {
  shield: <path d={SHIELD} />,
  "half-shield": (
    <>
      <path d={SHIELD} />
      <path d="M8 1.75 2.75 3.6v3.9c0 3.05 2.2 5.55 5.25 6.75V1.75Z" fill="currentColor" stroke="none" />
    </>
  ),
  eye: (
    <>
      <path d="M1.5 8S3.9 3.75 8 3.75 14.5 8 14.5 8 12.1 12.25 8 12.25 1.5 8 1.5 8Z" />
      <circle cx="8" cy="8" r="2.1" style={{ fill: `url(#${HATCH_PATTERN.ink}) currentColor` }} />
    </>
  ),
  triangle: (
    <>
      <path d="M8 2.25 14.5 13.5h-13L8 2.25Z" />
      <path d="M8 6.5v3" />
      <path d="M8 11.4v.1" strokeWidth="2" />
    </>
  ),
  "dashed-circle": <circle cx="8" cy="8" r="5.75" strokeDasharray="2.5 2" />,
  "hollow-circle": <circle cx="8" cy="8" r="5.75" />,
  "slashed-circle": (
    <>
      <circle cx="8" cy="8" r="5.75" />
      <path d="M3.95 12.05 12.05 3.95" />
    </>
  ),
  globe: (
    <>
      <circle cx="8" cy="8" r="6.25" />
      <path d="M1.75 8h12.5" />
      <ellipse cx="8" cy="8" rx="2.75" ry="6.25" />
    </>
  ),
  octagon: <path d="M5.4 1.75h5.2l3.65 3.65v5.2l-3.65 3.65H5.4L1.75 10.6V5.4L5.4 1.75Z" />,
  diamond: <path d="M8 1.75 14.25 8 8 14.25 1.75 8 8 1.75Z" />,
  circle: <circle cx="8" cy="8" r="6" />,
  square: <rect x="2.5" y="2.5" width="11" height="11" rx="1" />,
  copy: (
    <>
      <rect x="5.25" y="5.25" width="8.5" height="8.5" rx="1.25" />
      <path d="M10.75 5.25V3.5c0-.7-.55-1.25-1.25-1.25H3.5c-.7 0-1.25.55-1.25 1.25v6c0 .7.55 1.25 1.25 1.25h1.75" />
    </>
  ),
  "arrow-right": <path d="M2.5 8h11M9.5 4l4 4-4 4" />,
  terminal: (
    <>
      <rect x="1.75" y="2.75" width="12.5" height="10.5" rx="1.5" />
      <path d="m4.5 6.25 2.25 1.75-2.25 1.75M8.25 10h3.25" />
    </>
  ),
  plug: <path d="M5.75 1.75v3M10.25 1.75v3M3.75 4.75h8.5v2.5a4.25 4.25 0 0 1-8.5 0v-2.5ZM8 11.5v2.75" />,
};

export function Icon({ name, className = "h-4 w-4" }: { name: IconName; className?: string }) {
  return (
    <svg
      data-icon={name}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      className={`shrink-0 ${className}`}
    >
      {PATHS[name]}
    </svg>
  );
}
