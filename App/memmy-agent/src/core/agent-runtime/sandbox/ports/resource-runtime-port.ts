/** Terminates the concrete process, session, worker, and network context behind a lease. */
export interface ResourceRuntimePort {
  terminate(resourceId: string, reason: string): Promise<void>;
}
