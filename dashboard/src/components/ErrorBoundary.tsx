import { Component, ErrorInfo, ReactNode } from 'react'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false }

  static getDerivedStateFromError(): State {
    return { hasError: true }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    if (import.meta.env.DEV) {
      // eslint-disable-next-line no-console
      console.error('Uncaught render error:', error, info)
    }
  }

  reset = () => this.setState({ hasError: false })

  render() {
    if (!this.state.hasError) return this.props.children
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4 bg-slate-950 text-slate-400">
        <span className="text-5xl">💥</span>
        <p className="text-sm">Something went wrong.</p>
        <button
          onClick={this.reset}
          className="text-blue-400 hover:text-cyan-400 text-sm underline"
        >
          Try again
        </button>
      </div>
    )
  }
}
