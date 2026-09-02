export type CursorPage<T> = { data: T[]; pagination: { has_more: boolean; next_cursor?: string } }

export function advanceCursor(pagination: CursorPage<unknown>['pagination'], seenCursors: Set<string>): string | undefined {
  if (!pagination.has_more) return undefined
  const next = pagination.next_cursor?.trim()
  if (!next || seenCursors.has(next)) throw new Error('INVALID_PAGINATION_CURSOR')
  seenCursors.add(next)
  return next
}

export async function collectAllPages<T>(load: (cursor?: string) => Promise<CursorPage<T>>): Promise<T[]> {
  const result: T[] = []
  const seenCursors = new Set<string>()
  let cursor: string | undefined
  while (true) {
    const page = await load(cursor)
    result.push(...page.data)
    cursor = advanceCursor(page.pagination, seenCursors)
    if (!cursor) return result
  }
}
