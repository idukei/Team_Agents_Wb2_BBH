import { create } from 'zustand'

interface AgentStatus {
  phase:          string
  iteration:      number
  last_finding:   unknown
  active:         boolean
  findings_count: number
}

interface PendingInterrupt {
  interrupt_type: string
  hitl_id:        string
  label:          string
  description:    string
  operator_can:   string[]
  payload:        Record<string, unknown>
  thread_id:      string
  timestamp:      string
}

interface RunState {
  threadId:          string | null
  run:               Record<string, unknown> | null
  phase:             string | null
  agentStatus:       Record<string, AgentStatus>
  agentLoadouts:     Record<string, unknown>
  pendingInterrupts: PendingInterrupt[]
  findings:          unknown[]
  isStreaming:       boolean
  events:            unknown[]

  setThreadId:       (id: string) => void
  setRun:            (run: Record<string, unknown>) => void
  setPhase:          (phase: string) => void
  addEvent:          (event: unknown) => void
  addInterrupt:      (interrupt: PendingInterrupt) => void
  clearInterrupts:   () => void
  updateAgentStatus: (agentId: string, status: Partial<AgentStatus>) => void
  setAgentLoadouts:  (loadouts: Record<string, unknown>) => void
  setIsStreaming:    (v: boolean) => void
  reset:             () => void
}

export const useRunStore = create<RunState>((set) => ({
  threadId:          null,
  run:               null,
  phase:             null,
  agentStatus:       {},
  agentLoadouts:     {},
  pendingInterrupts: [],
  findings:          [],
  isStreaming:       false,
  events:            [],

  setThreadId: (id)  => set({ threadId: id }),

  setRun: (run) => set((s) => {
    const stateObj  = (run?.state || {}) as Record<string,unknown>
    const loadouts  = (stateObj.agent_loadouts || {}) as Record<string,unknown>
    return {
      run,
      agentLoadouts: Object.keys(loadouts).length > 0 ? loadouts : s.agentLoadouts,
    }
  }),

  setPhase:  (ph) => set({ phase: ph }),

  addEvent: (event) => set((s) => ({
    events: [...s.events.slice(-199), event],
  })),

  addInterrupt: (interrupt) => set((s) => ({
    pendingInterrupts: [...s.pendingInterrupts, interrupt],
  })),

  clearInterrupts: () => set({ pendingInterrupts: [] }),

  updateAgentStatus: (agentId, status) => set((s) => ({
    agentStatus: {
      ...s.agentStatus,
      [agentId]: { ...(s.agentStatus[agentId] || {}), ...status } as AgentStatus,
    },
  })),

  setAgentLoadouts: (loadouts) => set({ agentLoadouts: loadouts }),

  setIsStreaming: (v) => set({ isStreaming: v }),

  reset: () => set({
    threadId: null, run: null, phase: null,
    agentStatus: {}, agentLoadouts: {}, pendingInterrupts: [],
    findings: [], isStreaming: false, events: [],
  }),
}))
