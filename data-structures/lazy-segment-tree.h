#ifndef LAZY_SEGMENT_TREE
#define LAZY_SEGMENT_TREE

#include "stddef.h"

/// --------------------------------------------------------------------------------------------------------------------
/// Type declarations

typedef struct _SumSegmentTree SumSegmentTree;

struct _SumSegmentTree {
    size_t n;
    int *value;
    int *lazy;
};


/// --------------------------------------------------------------------------------------------------------------------
/// Methods

SumSegmentTree
*SumSegmentTree_create (size_t quantity);

void
SumSegmentTree_free (SumSegmentTree *self);

void
SumSegmentTree_modify (SumSegmentTree *self, size_t x, size_t y, int val);

int
SumSegmentTree_query (SumSegmentTree *self, int x);

#endif
