import { useState, useEffect } from "react";
import { Link, useLocation } from "wouter";
import {
  LayoutDashboard,
  ListChecks,
  Settings,
  Activity,
  Zap,
  PanelLeftClose,
  PanelLeftOpen,
  FolderKanban,
  ScanLine,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useHealthCheck } from "@workspace/api-client";

export function Shell({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem("sidebar-collapsed") === "true"
  );

  useEffect(() => {
    localStorage.setItem("sidebar-collapsed", String(collapsed));
  }, [collapsed]);

  const { data: health } = useHealthCheck();
  const isOnline = health?.status === "ok" || !health;
  const [activeScanCount, setActiveScanCount] = useState(0);

  useEffect(() => {
    let mounted = true;
    const refreshActiveScans = async () => {
      try {
        const response = await fetch("/api/scans", { cache: "no-store" });
        if (!response.ok) return;
        const scans = (await response.json()) as Array<{ status?: string }>;
        if (mounted) {
          setActiveScanCount(
            scans.filter(
              (scan) => scan.status === "pending" || scan.status === "running"
            ).length
          );
        }
      } catch {
        // Health indicator remains the source of truth when scan history is unavailable.
      }
    };

    void refreshActiveScans();
    const timer = window.setInterval(refreshActiveScans, 5000);
    return () => {
      mounted = false;
      window.clearInterval(timer);
    };
  }, []);

  const toggleSidebar = () => setCollapsed(!collapsed);

  const navItems = [
    {
      href: "/",
      label: "Dashboard",
      icon: LayoutDashboard,
      exact: true,
      badge: null,
    },
    {
      href: "/scan",
      label: "Scan Engine",
      icon: ScanLine,
      exact: true,
      badge: null,
    },
    {
      href: "/projects",
      label: "Projects",
      icon: FolderKanban,
      exact: false,
      badge: null,
    },
    {
      href: "/scans",
      label: "All Scans",
      icon: ListChecks,
      exact: true,
      badge: activeScanCount > 0 ? activeScanCount : null,
    },
  ];

  const isActive = (href: string, exact: boolean) => {
    if (exact) return location === href;
    return location.startsWith(href);
  };

  return (
    <div className="flex h-[100dvh] w-full bg-background overflow-hidden text-foreground">
      {/* Sidebar */}
      <aside
        className={cn(
          "flex-shrink-0 flex flex-col border-r border-border transition-all duration-300 relative z-20 bg-sidebar",
          collapsed ? "w-16" : "w-64"
        )}
      >
        {/* Toggle Button */}
        <button
          onClick={toggleSidebar}
          className="absolute -right-3 top-6 bg-card border border-border rounded-full p-1 hover:bg-accent hover:text-primary z-50 shadow-sm"
        >
          {collapsed ? (
            <PanelLeftOpen className="w-3 h-3" />
          ) : (
            <PanelLeftClose className="w-3 h-3" />
          )}
        </button>

        {/* Logo */}
        <div className="h-16 flex items-center px-4 border-b border-border flex-shrink-0">
          <div className="flex items-center gap-3 overflow-hidden w-full">
            {/* Brand shield icon — matches favicon */}
            <div className="w-8 h-8 flex-shrink-0 glow-primary">
              <svg viewBox="0 0 180 180" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
                <rect width="180" height="180" rx="36" fill="hsl(240 10% 6%)"/>
                <path d="M90 22L40 50v44c0 32 26 59 50 64 24-5 50-32 50-64V50L90 22z"
                      fill="hsl(150 100% 50% / 0.06)"/>
                <path d="M90 22L40 50v44c0 32 26 59 50 64 24-5 50-32 50-64V50L90 22z"
                      stroke="hsl(150 100% 50%)" strokeWidth="5" strokeLinejoin="round" strokeLinecap="round"/>
                <line x1="68" y1="76" x2="112" y2="110" stroke="hsl(150 100% 50%)" strokeWidth="9" strokeLinecap="round"/>
                <line x1="112" y1="76" x2="68"  y2="110" stroke="hsl(150 100% 50%)" strokeWidth="9" strokeLinecap="round"/>
              </svg>
            </div>
            {!collapsed && (
              <div className="whitespace-nowrap transition-opacity duration-300">
                <div className="font-mono font-bold text-base tracking-tight leading-none text-foreground">
                  SentinelX
                </div>
                <div className="text-[9px] text-muted-foreground font-mono tracking-widest leading-none mt-1">
                  SECURITY OPS
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Health Indicator */}
        <div className="px-3 pt-4">
          {!collapsed ? (
            <div
              className={cn(
                "px-3 py-2 rounded-md border flex items-center gap-2",
                isOnline
                  ? "bg-emerald-500/10 border-emerald-500/20"
                  : "bg-red-500/10 border-red-500/20"
              )}
            >
              <Activity
                className={cn(
                  "w-3 h-3 flex-shrink-0",
                  isOnline ? "text-emerald-400" : "text-red-400"
                )}
              />
              <span
                className={cn(
                  "text-[10px] font-mono tracking-wide",
                  isOnline ? "text-emerald-400" : "text-red-400"
                )}
              >
                {isOnline ? "SYSTEM ONLINE" : "DEGRADED"}
              </span>
              <span
                className={cn(
                  "ml-auto w-1.5 h-1.5 rounded-full animate-pulse",
                  isOnline ? "bg-emerald-400" : "bg-red-400"
                )}
              />
            </div>
          ) : (
            <div className="flex justify-center mt-1">
              <span
                className={cn(
                  "w-2 h-2 rounded-full animate-pulse",
                  isOnline ? "bg-emerald-400" : "bg-red-400"
                )}
                title={isOnline ? "System Online" : "Degraded"}
              />
            </div>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 pt-6 space-y-1 overflow-hidden">
          {!collapsed && (
            <div className="text-[10px] font-mono text-muted-foreground/50 tracking-widest px-3 mb-3 uppercase">
              Workspace
            </div>
          )}

          {navItems.map(({ href, label, icon: Icon, exact, badge }) => {
            const active = isActive(href, exact);
            return (
              <Link
                key={href}
                href={href}
                title={collapsed ? label : undefined}
                className={cn(
                  "flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-all group relative",
                  active
                    ? "nav-active text-primary bg-primary/5"
                    : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
                )}
              >
                <Icon
                  className={cn(
                    "w-4 h-4 flex-shrink-0",
                    active ? "text-primary" : "group-hover:text-foreground"
                  )}
                />
                {!collapsed && <span>{label}</span>}
                {badge !== null && badge > 0 && (
                  <span
                    className={cn(
                      "min-w-5 rounded-full border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-center text-[9px] font-mono font-bold text-primary",
                      collapsed
                        ? "absolute right-1 top-1"
                        : "ml-auto"
                    )}
                  >
                    {badge}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        {/* System & Footer */}
        <div className="px-3 pb-4 space-y-1 border-t border-border pt-3 mt-3">
          {!collapsed && (
            <div className="text-[10px] font-mono text-muted-foreground/50 tracking-widest px-3 mb-2 uppercase">
              System
            </div>
          )}
          <Link
            href="/settings"
            title={collapsed ? "Settings" : undefined}
            className={cn(
              "flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-all group",
              location === "/settings"
                ? "nav-active text-primary bg-primary/5"
                : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
            )}
          >
            <Settings
              className={cn(
                "w-4 h-4 flex-shrink-0",
                location === "/settings"
                  ? "text-primary"
                  : "group-hover:text-foreground"
              )}
            />
            {!collapsed && <span>Settings</span>}
          </Link>

          <div
            className={cn(
              "flex items-center gap-2 pt-3",
              collapsed ? "justify-center px-0" : "px-3"
            )}
          >
            <Zap className="w-3 h-3 text-muted-foreground/40" />
            {!collapsed && (
              <span className="text-[10px] font-mono text-muted-foreground/40">
                v0.3.0
              </span>
            )}
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 overflow-auto relative bg-grid-pattern">
        <div className="relative z-10 min-h-full p-8 max-w-[1600px] mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
}
