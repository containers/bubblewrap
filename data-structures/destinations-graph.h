#pragma once

#include "../utils.h"
#include "lazy-segment-tree.h"

/// --------------------------------------------------------------------------------------------------------------------
/// Type declarations

typedef struct _DestinationsGraph DestinationsGraph;

typedef struct _DestinationsGraph_Node DestinationsGraph_Node;

typedef struct _DestinationsLinkedList_Node DestinationsLinkedList_Node;

typedef struct _DestinationsLinkedList DestinationsLinkedList;

struct _DestinationsGraph_Node {

    char *path_part;  /* Parts of slash-separated path. Could be directory or file name */

    bool is_mount_point;    /* Whether it is a mount point we want to bind or simple path of path. */
    char *source;     /* == NULL when is_mount_point == FALSE */
    char *dest;       /* == NULL when is_mount_point == FALSE */

    DestinationsLinkedList *children;

    unsigned int euler_tour_start;
    unsigned int euler_tour_end;

};

struct _DestinationsGraph {

    DestinationsGraph_Node *root;

    unsigned int count_nodes;
    unsigned int count_mount_points;

    unsigned int _euler_tour_timer;

    SumSegmentTree* nodev;
    SumSegmentTree* readonly;

};

struct _DestinationsLinkedList_Node {
    DestinationsGraph_Node *value;
    DestinationsLinkedList_Node *next;
};

struct _DestinationsLinkedList {
    DestinationsLinkedList_Node *head;
    DestinationsLinkedList_Node *tail;
    int count;
};

/// ---------------------------------------------------------------------------------------------------------------------
/// Default methods of DestinationsGraph

DestinationsGraph *
DestinationsGraph_create (void);

void
DestinationsGraph_free (DestinationsGraph *self);

DestinationsGraph_Node *
DestinationsGraph_ensure_mount_point (DestinationsGraph *self, char **destination_path, bool *added);

void
DestinationsGraph__euler_tour__ (DestinationsGraph *self);

void
DestinationsGraph_debug_pretty_print (DestinationsGraph *self, FILE *fd);

/// --------------------------------------------------------------------------------------------------------------------
/// Nodes methods of DestinationsGraph

DestinationsGraph_Node *
DestinationsGraph_Node_create (void);

void
DestinationsGraph_Node_free (DestinationsGraph_Node *self);

void
DestinationsGraph_Node__free_recursive__ (DestinationsGraph_Node *self);

void
DestinationsGraph_Node__euler_tour__ (DestinationsGraph *graph, DestinationsGraph_Node *self);

void
DestinationsGraph_Node_debug_pretty_print (FILE *fd, DestinationsGraph_Node *current, int depth);

/// --------------------------------------------------------------------------------------------------------------------
/// Linked list methods of DestinationsGraph

DestinationsLinkedList *
DestinationsLinkedList_create (void);

void
DestinationsLinkedList_free (DestinationsLinkedList *self);

void
DestinationsLinkedList_push_back (DestinationsLinkedList *self,
                                  DestinationsGraph_Node *node);

DestinationsGraph_Node*
DestinationsLinkedList_find_by_path_part (DestinationsLinkedList *self,
                                          char *path_part);

/// ---------------------------------------------------------------------------------------------------------------------
/// Flags-related methods of DestinationsGraph

void
DestinationsGraph_Flags_init (DestinationsGraph *self);

void
DestinationsGraph_Flags__set_flag__ (SumSegmentTree *segment_tree, DestinationsGraph_Node *node);

void
DestinationsGraph_Flags__unset_flag__ (SumSegmentTree *segment_tree, DestinationsGraph_Node *node);

bool
DestinationsGraph_Flags__check_flag__ (SumSegmentTree *segment_tree, DestinationsGraph_Node *node);

void
DestinationsGraph_Flags_set_readonly (DestinationsGraph *self, DestinationsGraph_Node *node);

void
DestinationsGraph_Flags_unset_readonly (DestinationsGraph *self, DestinationsGraph_Node *node);

bool
DestinationsGraph_Flags_check_readonly (DestinationsGraph *self, DestinationsGraph_Node *node);

void
DestinationsGraph_Flags_set_nodev (DestinationsGraph *self, DestinationsGraph_Node *node);

void
DestinationsGraph_Flags_unset_nodev (DestinationsGraph *self, DestinationsGraph_Node *node);

bool
DestinationsGraph_Flags_check_nodev (DestinationsGraph *self, DestinationsGraph_Node *node);
