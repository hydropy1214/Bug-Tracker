import { Link, useLocation } from "wouter";
import { ShieldAlert, LayoutDashboard, FolderKanban, Settings, Activity, Zap } from "lucide-react";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { href: "/", icon: LayoutDashboard, label: "Dashboard", exact: true },
  { href: "/projects", icon: FolderKanban, label: "Projects", exact: false },
];

function NavItem({ href, icon: Icon, label, active }: { href: string; icon: any; label: string; active: boolean }) {
  return (
    <Link
      href={href}
      className={cn(
        "flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group relative",
        active
          ? "nav-active text-primary"
          : "text-muted-foreground hover:text-foreground hover:bg-accent/60 border-l-2 border-transparent"
      )}
    >
      <Icon className={cn("w-4 h-4 flex-shrink-0 transition-colors", active ? "text-primary" : "group-hover:text-foreground")} />
      <span>{label}</span>
      {active && (
        <span className="ml-auto w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
      )}
    </Link>
  );
}

export function Shell({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();

  return (
    <div className="flex h-[100dvh] w-full bg-background bg-grid-pattern overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 flex-shrink-0 flex flex-col border-r border-border/60" style={{ background: 'hsl(var(--sidebar))' }}>
        {/* Logo */}
        <div className="h-16 flex items-center px-5 border-b border-border/60">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="w-8 h-8 rounded-lg bg-primary/15 flex items-center justify-center glow-primary">
                <ShieldAlert className="w-4 h-4 text-primary" />
              </div>
              <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-400 border-2 border-sidebar" style={{ borderColor: 'hsl(var(--sidebar))' }} />
            </div>
            <div>
              <span className="font-mono font-bold text-base tracking-tight text-foreground">SentinelX</span>
              <div className="text-[10px] text-muted-foreground font-mono tracking-widest">SECURITY OPS</div>
            </div>
          </div>
        </div>

        {/* Live indicator bar */}
        <div className="mx-4 mt-4 px-3 py-2 rounded-md bg-emerald-500/8 border border-emerald-500/20 flex items-center gap-2">
          <Activity className="w-3 h-3 text-emerald-400 flex-shrink-0" />
          <span className="text-[11px] text-emerald-400 font-mono tracking-wide">SYSTEM ONLINE</span>
          <span className="ml-auto w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
        </div>

        {/* Nav section */}
        <nav className="flex-1 px-3 pt-5 space-y-1">
          <div className="text-[10px] font-mono text-muted-foreground/60 tracking-widest px-4 mb-2 uppercase">Navigation</div>
          {NAV_ITEMS.map(({ href, icon, label, exact }) => (
            <NavItem
              key={href}
              href={href}
              icon={icon}
              label={label}
              active={exact ? location === href : location.startsWith(href)}
            />
          ))}
        </nav>

        {/* Footer */}
        <div className="px-3 pb-4 space-y-1 border-t border-border/60 pt-3 mt-3">
          <NavItem
            href="/settings"
            icon={Settings}
            label="Settings"
            active={location === "/settings"}
          />
          <div className="flex items-center gap-2 px-4 pt-3">
            <Zap className="w-3 h-3 text-muted-foreground/40" />
            <span className="text-[10px] font-mono text-muted-foreground/40">v0.1.0</span>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto relative">
        {/* Subtle scanline overlay */}
        <div className="pointer-events-none absolute inset-0 z-0 opacity-[0.015]"
          style={{ backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,255,255,1) 2px, rgba(255,255,255,1) 3px)', backgroundSize: '100% 3px' }}
        />
        <div className="relative z-10 h-full p-8 max-w-7xl mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
}
