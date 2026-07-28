import { Component, type ReactNode } from 'react';
import { Shield, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: { componentStack: string }) {
    console.error('[ErrorBoundary] Uncaught render error:', error, info);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.replace('/');
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex h-[100dvh] w-full items-center justify-center bg-background text-foreground">
          <div className="flex flex-col items-center gap-6 text-center max-w-sm px-4">
            <div className="w-16 h-16 rounded-md border border-red-500/30 bg-red-500/10 flex items-center justify-center">
              <Shield className="w-7 h-7 text-red-400" />
            </div>
            <div>
              <div className="font-mono font-bold text-lg text-foreground uppercase tracking-wider">
                Something went wrong
              </div>
              <p className="text-[11px] font-mono text-muted-foreground mt-2 leading-relaxed">
                An unexpected error occurred. Click below to return to the dashboard.
              </p>
            </div>
            {this.state.error && (
              <pre className="text-[9px] font-mono text-red-400/70 bg-red-500/5 border border-red-500/20 rounded-sm px-3 py-2 max-w-full overflow-auto text-left whitespace-pre-wrap">
                {this.state.error.message}
              </pre>
            )}
            <button
              onClick={this.handleReset}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-sm border border-primary/40 bg-primary/5 text-primary text-[10px] font-mono uppercase tracking-widest hover:bg-primary/10 transition-all"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Return to Dashboard
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
