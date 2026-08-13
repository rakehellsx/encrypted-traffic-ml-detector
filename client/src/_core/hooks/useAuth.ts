import { trpc } from "@/lib/trpc";

export function useAuth() {
  const meQuery = trpc.auth.me.useQuery(undefined, { refetchOnWindowFocus: false });
  return {
    user: meQuery.data ?? null,
    loading: meQuery.isLoading,
    error: meQuery.error ?? null,
    isAuthenticated: true,
    refresh: () => meQuery.refetch(),
    logout: async () => undefined,
  };
}
