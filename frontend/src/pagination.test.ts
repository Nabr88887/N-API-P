import { expect, it, vi } from 'vitest'

import { advanceCursor, collectAllPages } from './pagination'

it('collects every unique page until pagination completes', async () => {
  const load = vi.fn()
    .mockResolvedValueOnce({ data: [{ id: 'one' }], pagination: { has_more: true, next_cursor: 'page-2' } })
    .mockResolvedValueOnce({ data: [{ id: 'two' }], pagination: { has_more: false } })

  await expect(collectAllPages(load)).resolves.toEqual([{ id: 'one' }, { id: 'two' }])
  expect(load).toHaveBeenNthCalledWith(1, undefined)
  expect(load).toHaveBeenNthCalledWith(2, 'page-2')
})

it('fails closed when a paged endpoint repeats a cursor', async () => {
  const load = vi.fn()
    .mockResolvedValueOnce({ data: [{ id: 'one' }], pagination: { has_more: true, next_cursor: 'repeated' } })
    .mockResolvedValueOnce({ data: [{ id: 'two' }], pagination: { has_more: true, next_cursor: 'repeated' } })

  await expect(collectAllPages(load)).rejects.toThrow('INVALID_PAGINATION_CURSOR')
  expect(load).toHaveBeenCalledTimes(2)
})

it('fails closed when has_more has no continuation cursor', async () => {
  const load = vi.fn().mockResolvedValue({ data: [{ id: 'one' }], pagination: { has_more: true } })

  await expect(collectAllPages(load)).rejects.toThrow('INVALID_PAGINATION_CURSOR')
  expect(load).toHaveBeenCalledOnce()
})

it('rejects a repeated continuation cursor for manual pagination', () => {
  const seen = new Set<string>()

  expect(() => advanceCursor({ has_more: true, next_cursor: 'page-2' }, seen)).not.toThrow()
  expect(() => advanceCursor({ has_more: true, next_cursor: 'page-2' }, seen)).toThrow('INVALID_PAGINATION_CURSOR')
})

it('rejects a missing continuation cursor for manual pagination', () => {
  expect(() => advanceCursor({ has_more: true }, new Set())).toThrow('INVALID_PAGINATION_CURSOR')
})
