import { useCallback, useEffect, useRef, useState, type UIEvent } from "react";

export const ARTIFACT_PAGE_SIZE = 20;

type PageResult<T> = { items: T[]; total: number };

/**
 * Load artifact/evidence rows a page at a time and append on scroll.
 *
 * Why this is not just `items.length < total`:
 * the server reports `total` as a raw COUNT(*) of the family/scope, but then
 * drops rows *after* counting (runtime-junk stripping, file-type filtering,
 * client-side group filtering, cross-page de-duplication of carved artifacts
 * that can share an id). A page can therefore return fewer new rows than
 * `pageSize`, or zero new rows, while `items.length` is still below `total`.
 * The old guard `items.length < total` then stayed true forever, but nothing
 * advanced `items.length`, so the list froze part-way with "scroll for more"
 * still showing and no way to recover.
 *
 * This version tracks what each fetch actually returned and added, and stops
 * only when the server runs out of rows, reaching the real end of the data
 * regardless of how many rows each page drops.
 */
export function useInfiniteArtifactPage<T extends { id: string }>(
  resetKey: string,
  fetchPage: (page: number, pageSize: number) => Promise<PageResult<T>>
) {
  const [items, setItems] = useState<T[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  // True once a fetch has proven there are no more rows on the server.
  const [reachedEnd, setReachedEnd] = useState(false);

  const busyRef = useRef(false);
  const pageRef = useRef(1);
  const reachedEndRef = useRef(false);
  // Consecutive pages that returned rows but added nothing new (all duplicates
  // or all filtered). Bounded so a run of fully-dropped pages cannot loop forever.
  const emptyStreakRef = useRef(0);
  const fetchRef = useRef(fetchPage);
  fetchRef.current = fetchPage;

  const MAX_EMPTY_STREAK = 5;

  const load = useCallback(async (pageToLoad: number, append: boolean) => {
    if (busyRef.current) return;
    if (append && reachedEndRef.current) return;
    busyRef.current = true;
    if (append) setLoadingMore(true);
    else setLoading(true);
    try {
      const res = await fetchRef.current(pageToLoad, ARTIFACT_PAGE_SIZE);
      const returned = res.items.length;
      setTotal(res.total);
      pageRef.current = pageToLoad;

      let added = 0;
      setItems((prev) => {
        if (!append) {
          added = res.items.length;
          return res.items;
        }
        const seen = new Set(prev.map((row) => row.id));
        const fresh = res.items.filter((row) => !seen.has(row.id));
        added = fresh.length;
        return fresh.length ? [...prev, ...fresh] : prev;
      });

      // End of data: a short/empty page means nothing follows it; a run of pages
      // that add no new rows means the tail is all duplicates/filtered; or the
      // full reported total has been collected on the first page.
      const serverExhausted = returned < ARTIFACT_PAGE_SIZE;
      emptyStreakRef.current = added === 0 && returned > 0 ? emptyStreakRef.current + 1 : 0;
      const stuck = emptyStreakRef.current >= MAX_EMPTY_STREAK;
      const end = append
        ? serverExhausted || stuck
        : serverExhausted && res.items.length >= res.total;
      reachedEndRef.current = end;
      setReachedEnd(end);
    } catch {
      // A transient error must not permanently stop scrolling or claim the end.
    } finally {
      busyRef.current = false;
      setLoading(false);
      setLoadingMore(false);
    }
  }, []);

  useEffect(() => {
    setItems([]);
    setTotal(0);
    setReachedEnd(false);
    pageRef.current = 1;
    reachedEndRef.current = false;
    emptyStreakRef.current = 0;
    void load(1, false);
  }, [resetKey, load]);

  // More rows may exist unless a fetch has proven the server is exhausted.
  const hasMore = !reachedEnd;

  function onListScroll(event: UIEvent<HTMLElement>) {
    if (reachedEndRef.current || busyRef.current) return;
    const el = event.currentTarget;
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 96) {
      void load(pageRef.current + 1, true);
    }
  }

  return {
    items,
    setItems,
    total,
    loading,
    loadingMore,
    hasMore,
    reachedEnd,
    onListScroll,
    reload: () => {
      reachedEndRef.current = false;
      emptyStreakRef.current = 0;
      pageRef.current = 1;
      void load(1, false);
    },
  };
}
