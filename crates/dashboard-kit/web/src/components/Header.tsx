import { useEffect, useRef, useState, type ReactNode } from "react";
import { TechnicalDetailToggle } from "./TechnicalDetail";
import logo from "../assets/logo.svg";

/**
 * Where the tour's button goes: the header's own slot, inside the small-screen
 * menu with the technical switch. `TourLauncher` looks for it first.
 */
export const HEADER_TOUR_SLOT = "data-tour-slot";

export type HeaderNavigationItem<Route extends string> = {
  route: Route;
  label: string;
};

/**
 * Whether a key press closes the small-screen menu: Escape, the way every
 * menu that floats over a page closes.
 */
export function closesMenu(key: string): boolean {
  return key === "Escape";
}

export function Header<Route extends string>({
  editionLabel,
  version,
  navigation,
  activeRoute,
  homeRoute,
  onNavigate,
  status,
  account,
}: {
  editionLabel: string;
  version?: string;
  navigation: HeaderNavigationItem<Route>[];
  activeRoute: Route;
  homeRoute: Route;
  onNavigate: (route: Route) => void;
  status: ReactNode;
  /**
   * Who is signed in ("Signed in as alice"), said inside the small-screen
   * menu. Below 400 px the status badge keeps only its check, so the menu is
   * where a phone reader sees the name a change is recorded under.
   */
  account?: string;
}) {
  // Below the small breakpoint the switch and the tour sit behind one
  // button, so the header is one row over the nav instead of three: at 320
  // px it took 175 of 640 px before the page began.
  const [menuOpen, setMenuOpen] = useState(false);
  const menuButton = useRef<HTMLButtonElement>(null);
  const menuPanel = useRef<HTMLDivElement>(null);

  // The menu floats over the page, so it closes the ways a floating menu
  // does: Escape (focus back on its button), a press anywhere outside it,
  // and going to another screen.
  useEffect(() => {
    if (!menuOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (!closesMenu(event.key)) return;
      setMenuOpen(false);
      menuButton.current?.focus();
    };
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node | null;
      if (target !== null && (menuPanel.current?.contains(target) || menuButton.current?.contains(target))) return;
      setMenuOpen(false);
    };
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("pointerdown", onPointerDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("pointerdown", onPointerDown);
    };
  }, [menuOpen]);

  const navigate = (route: Route) => {
    setMenuOpen(false);
    onNavigate(route);
  };

  return (
    <header className="relative border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2 sm:gap-x-5 sm:gap-y-3 sm:px-6 sm:py-3 lg:px-8">
        <button
          type="button"
          onClick={() => navigate(homeRoute)}
          aria-label="Go to overview"
          title="Go to dashboard home"
          className="flex min-w-0 items-center gap-3 rounded-lg text-left transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-900 focus-visible:ring-offset-2"
        >
          <img src={logo} alt="InnerWarden" className="h-7 w-auto sm:h-9" />
          <div className="flex min-w-0 items-baseline gap-2 border-l border-slate-200 pl-3 leading-tight">
            <span className="text-sm font-semibold text-slate-900">{editionLabel}</span>
            {/* Below 400 px the version costs the header a row; it is one
                click away in the product's own status. */}
            {version ? <span className="hidden text-[11px] font-medium text-slate-500 min-[400px]:inline">v{version}</span> : null}
          </div>
        </button>

        {navigation.length > 0 ? (
          <nav
            className="order-3 flex w-full gap-1 border-t border-slate-100 pt-2 sm:order-none sm:w-auto sm:border-0 sm:pt-0"
            aria-label="Dashboard views"
            data-tour="nav"
          >
            {navigation.map((item) => (
              <button
                key={item.route}
                type="button"
                // The route, not only its label: this nav is the one place that
                // knows which screens this shell really offers, and the product
                // tour reads it back from here so it cannot walk an operator to
                // a tab that does not exist (see `stepsForShell`).
                data-route={item.route}
                onClick={() => navigate(item.route)}
                aria-current={activeRoute === item.route ? "page" : undefined}
                aria-pressed={activeRoute === item.route}
                className={`rounded-lg px-3 py-2 text-sm font-semibold transition-colors ${
                  activeRoute === item.route
                    ? "bg-slate-900 text-white"
                    : "text-slate-600 hover:bg-slate-100 hover:text-slate-950"
                }`}
              >
                {item.label}
              </button>
            ))}
          </nav>
        ) : null}

        {/* The switch lives here, next to the status, because that is where
          * someone looks when they want to know more about what they are being
          * told. Off by default: the plain answer is the one a buyer needs, and
          * the evidence is for whoever asks for it.
          *
          * `min-w-0`, so a long status (a 64-character name) wraps inside the
          * header instead of pushing it past the edge. */}
        <div className="ml-auto flex min-w-0 items-center gap-2 text-xs sm:gap-3">
          <button
            ref={menuButton}
            type="button"
            className="rounded-lg border border-slate-300 bg-white px-2 py-1 text-sm leading-4 text-slate-700 shadow-sm hover:bg-slate-100 sm:hidden"
            aria-label="Menu"
            aria-expanded={menuOpen}
            aria-controls="header-menu"
            onClick={() => setMenuOpen((open) => !open)}
          >
            <span aria-hidden="true">☰</span>
          </button>
          <div
            ref={menuPanel}
            id="header-menu"
            {...{ [HEADER_TOUR_SLOT]: "" }}
            className={`${menuOpen ? "absolute right-4 top-full z-40 mt-1 flex max-w-[calc(100vw-2rem)] flex-col items-start gap-3 rounded-xl border border-slate-200 bg-white p-3 shadow-lg" : "hidden"} sm:static sm:z-auto sm:mt-0 sm:flex sm:max-w-none sm:flex-row sm:items-center sm:gap-3 sm:rounded-none sm:border-0 sm:bg-transparent sm:p-0 sm:shadow-none`}
          >
            {account === undefined ? null : (
              <p data-header-account className="text-xs font-medium text-slate-700 [overflow-wrap:anywhere] min-[400px]:hidden">{account}</p>
            )}
            <TechnicalDetailToggle />
          </div>
          {status}
        </div>
      </div>
    </header>
  );
}
