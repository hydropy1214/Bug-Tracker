import { Link } from "wouter";
import { ShieldOff, Home } from "lucide-react";
import { motion } from "framer-motion";

export default function NotFound() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex flex-col items-center justify-center h-full w-full py-32 text-center"
    >
      {/* Icon */}
      <div className="w-16 h-16 rounded-md border border-border bg-card flex items-center justify-center mb-6">
        <ShieldOff className="w-7 h-7 text-muted-foreground/40" />
      </div>

      {/* Code */}
      <div className="font-mono font-bold text-5xl text-primary mb-2 stat-number-glow">404</div>

      {/* Message */}
      <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground mb-1">
        Resource not found
      </p>
      <p className="text-sm text-muted-foreground/60 max-w-xs mt-2">
        The page or endpoint you requested does not exist.
      </p>

      {/* CTA */}
      <Link
        href="/"
        className="mt-8 inline-flex items-center gap-2 px-4 py-2 rounded-sm border border-primary/40 bg-primary/5 text-primary text-[10px] font-mono uppercase tracking-widest hover:bg-primary/10 transition-all"
      >
        <Home className="w-3.5 h-3.5" />
        Back to Dashboard
      </Link>
    </motion.div>
  );
}
