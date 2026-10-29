import { Component, type ErrorInfo, type ReactNode } from "react";
import { Link } from "react-router-dom";

interface Props { children: ReactNode }
interface State { error: Error | null }

/** Keep an individual artifact page failure visible, not a blank application. */
export class ArtifactPageErrorBoundary extends Component<Props, State> {
  state: State = { error: null };
  static getDerivedStateFromError(error: Error): State { return { error }; }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Disk artifact page rendering failed", error, info.componentStack);
  }
  render() {
    if (!this.state.error) return this.props.children;
    return <main className="mx-auto max-w-3xl p-8">
      <h1 className="text-xl font-bold">Disk artifacts could not be displayed</h1>
      <p className="mt-2 text-sm">The evidence has not been changed. This is an application display error.</p>
      <pre className="mt-4 overflow-auto rounded border p-3 text-xs" role="alert">{this.state.error.message}</pre>
      <button type="button" className="mt-4 rounded border px-4 py-2" onClick={() => this.setState({ error: null })}>Retry display</button>
      <Link className="ml-4 underline" to="/forensic/artifacts">Back to artifact jobs</Link>
    </main>;
  }
}
