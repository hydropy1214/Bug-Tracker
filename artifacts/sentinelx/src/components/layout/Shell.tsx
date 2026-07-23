import { Link, useLocation } from "wouter";
import { ShieldAlert, LayoutDashboard, FolderKanban, Settings } from "lucide-react";
import { cn } from "@/lib/utils";

export function Shell({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();

  return (
    <div className="flex h-[100dvh] w-full bg-background bg-grid-pattern">
      <aside className="w-64 border-r border-border bg-card/50 backdrop-blur-xl flex flex-col">
        <div className="h-14 flex items-center px-4 border-b border-border">
          <ShieldAlert className="w-6 h-6 text-primary mr-2" />
          <span className="font-mono font-bold text-lg tracking-tight">SentinelX</span>
        </div>
        <nav className="flex-1 p-4 space-y-1">
          <Link href="/" className={cn(
            "flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors",
            location === "/" ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
          )}>
            <LayoutDashboard className="w-4 h-4 mr-3" />
            Dashboard
          </Link>
          <Link href="/projects" className={cn(
            "flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors",
            location.startsWith("/projects") ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
          )}>
            <FolderKanban className="w-4 h-4 mr-3" />
            Projects
          </Link>
        </nav>
        <div className="p-4 border-t border-border">
            <Link href="/settings" className={cn(
            "flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors",
            location === "/settings" ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
          )}>
            <Settings className="w-4 h-4 mr-3" />
            Settings
          </Link>
        </div>
      </aside>
      <main className="flex-1 overflow-auto">
        <div className="h-full p-8 max-w-7xl mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
}
