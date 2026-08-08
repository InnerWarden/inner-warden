import type { ReactNode } from "react";
import logo from "../assets/logo.svg";

export type HeaderNavigationItem<Route extends string> = {
  route: Route;
  label: string;
};

export function Header<Route extends string>({
  editionLabel,
  version,
  navigation,
  activeRoute,
  homeRoute,
  onNavigate,
  status,
}: {
  editionLabel: string;
  version?: string;
  navigation: HeaderNavigationItem<Route>[];
  activeRoute: Route;
  homeRoute: Route;
  onNavigate: (route: Route) => void;
  status: ReactNode;
}) {
  return (
    <header className="border-b border-slate-200 bg-white">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-5 gap-y-3 px-4 py-3 sm:px-6 lg:px-8">
        <button
          type="button"
          onClick={() => onNavigate(homeRoute)}
          aria-label="Go to overview"
          title="Go to dashboard home"
          className="flex min-w-0 items-center gap-3 rounded-lg text-left transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-900 focus-visible:ring-offset-2"
        >
          <img src={logo} alt="InnerWarden" className="h-8 w-auto sm:h-9" />
          <div className="flex min-w-0 items-baseline gap-2 border-l border-slate-200 pl-3 leading-tight">
            <span className="text-sm font-semibold text-slate-900">{editionLabel}</span>
            {version ? <span className="text-[11px] font-medium text-slate-500">v{version}</span> : null}
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
                onClick={() => onNavigate(item.route)}
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

        <div className="ml-auto flex items-center gap-2 text-xs">{status}</div>
      </div>
    </header>
  );
}
