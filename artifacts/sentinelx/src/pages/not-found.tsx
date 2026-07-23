export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-full w-full">
      <h1 className="text-4xl font-bold font-mono text-primary mb-4">404</h1>
      <p className="text-muted-foreground">The resource you requested could not be found.</p>
    </div>
  );
}