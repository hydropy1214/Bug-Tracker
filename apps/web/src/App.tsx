import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import NotFound from '@/pages/not-found';
import { Route, Switch, Router as WouterRouter, Redirect } from 'wouter';
import { Shell } from '@/components/layout/Shell';
import { HomeDashboard } from '@/pages/HomeDashboard';
import { ScanEngine } from '@/pages/ScanEngine';
import { Scans } from '@/pages/Scans';
import { Settings } from '@/pages/Settings';
import { Projects } from '@/pages/Projects';
import { ProjectDetail } from '@/pages/ProjectDetail';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 10_000,
    },
  },
});

function Router() {
  return (
    <Shell>
      <Switch>
        {/* Home dashboard */}
        <Route path="/" component={HomeDashboard} />

        {/* Scan engine — quick scan */}
        <Route path="/scan" component={ScanEngine} />

        {/* Projects */}
        <Route path="/projects" component={Projects} />
        <Route path="/projects/:id/:tab">
          {(params) => (
            <ProjectDetail
              params={{ id: params.id }}
              defaultTab={(params.tab as 'assets' | 'findings' | 'scans') || 'assets'}
            />
          )}
        </Route>
        <Route path="/projects/:id">
          {(params) => <ProjectDetail params={{ id: params.id }} defaultTab="assets" />}
        </Route>

        {/* Scan history */}
        <Route path="/scans" component={Scans} />

        {/* Settings / System */}
        <Route path="/settings" component={Settings} />

        {/* Legacy redirect: old root was the scan engine */}
        <Route path="/dashboard">
          <Redirect to="/" />
        </Route>

        {/* 404 */}
        <Route component={NotFound} />
      </Switch>
    </Shell>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}>
        <Router />
      </WouterRouter>
      <Toaster theme="dark" position="bottom-right" richColors />
    </QueryClientProvider>
  );
}

export default App;
