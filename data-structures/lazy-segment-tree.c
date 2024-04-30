#ifndef LAZY_SEGMENT_TREE_OPS
#define LAZY_SEGMENT_TREE_OPS

#include "lazy-segment-tree.h"
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>

/// --------------------------------------------------------------------------------------------------------------------
/// Constructing and destructing object

SumSegmentTree
*SumSegmentTree_create (size_t quantity)
{
  SumSegmentTree *self =  xcalloc(1, sizeof (SumSegmentTree));
  assert(quantity > 0);

  // levels = log2(quantity - 1)
  size_t under_logarithm = quantity - 1;
  size_t levels = 1;
  while (under_logarithm >>= 1) levels++;

  // self->n = (levels + 1) ^ 2
  self->n = (1 << (levels + 1));

  size_t elements = self->n * 2;

  self->value = xcalloc (elements, sizeof (int));
  self->lazy = xcalloc (elements, sizeof (int));

  return self;
}

void
SumSegmentTree_free (SumSegmentTree *self)
{
  self->n = 0;
  free (self->value);
  free (self->lazy);
  free (self);
}

/// --------------------------------------------------------------------------------------------------------------------
/// Private methods

static void
SumSegmentTree__push__ (SumSegmentTree *self, size_t v, size_t l, size_t r);

static void
SumSegmentTree__modify__ (SumSegmentTree *self, size_t x, size_t y, int val, size_t root, size_t l, size_t r);

static int
SumSegmentTree__query__ (SumSegmentTree *self, size_t x, size_t y, size_t root, size_t l, size_t r);

static void
SumSegmentTree__push__ (SumSegmentTree *self, size_t v, size_t l, size_t r)
{
  if (self->lazy[v] != -1 && v < self->n)
    {
      size_t mid = (l + r) / 2;

      // Left child = lazy[current] * left segment length
      self->value[v << 1] = (int) (self->lazy[v] * (mid - l));

      // Right child = lazy[current] * right segment length
      self->value[v << 1 | 1] = (int) (self->lazy[v] * (r - mid));

      // Lazy propagate value to subtrees
      self->lazy[v << 1] = self->lazy[v];
      self->lazy[v << 1 | 1] = self->lazy[v];
      self->lazy[v] = -1;
    }
}

static void
SumSegmentTree__modify__ (SumSegmentTree *self, size_t x, size_t y, int val, size_t root, size_t l, size_t r)
{
  // Return if we are out of desired segment
  if (x >= r || y <= l)
    return;

  // If we are fully in desired segment
  // Then assign value in lazy way
  if (x <= l && r <= y)
    {
      self->lazy[root] = val;
      self->value[root] = val * (int) (r - l);
      return;
    }

  // Lazy propagate existing changes
  SumSegmentTree__push__ (self, root, l, r);

  size_t mid = (l + r) / 2;

  // Perform the same operation for left and right subtrees
  SumSegmentTree__modify__ (self, x, y, val, root << 1, l, mid);
  SumSegmentTree__modify__ (self, x, y, val, root << 1 | 1, mid, r);

  self->value[root] = self->value[root << 1] + self->value[root << 1 | 1];
}

static int
SumSegmentTree__query__ (SumSegmentTree *self, size_t x, size_t y, size_t root, size_t l, size_t r)
{
  // If we are outside of desired segment, return 0
  // Because current implementation of segment tree calculates sums on segments,
  // 0 is okay for us and won't change query result in unexpected way
  if (x >= r || y <= l)
    return 0;

  // If we are fully in requested segment, we can just return value
  if (x <= l && r <= y)
    return self->value[root];

  // Otherwise, we propagate lazy value and recurse into subtrees
  SumSegmentTree__push__ (self, root, l, r);

  size_t mid = (l + r) >> 1;

  return SumSegmentTree__query__ (self, x, y, root << 1, l, mid) + \
         SumSegmentTree__query__ (self, x, y, root << 1 | 1, mid, r);
}

/// --------------------------------------------------------------------------------------------------------------------
/// Public methods

void
SumSegmentTree_modify (SumSegmentTree *self, size_t x, size_t y, int val)
{
  SumSegmentTree__modify__ (self, x, y, val, 1, 0, self->n);
}

int
SumSegmentTree_query (SumSegmentTree *self, int x)
{
  return SumSegmentTree__query__ (self, x, x + 1, 1, 0, self->n);
}

#endif
