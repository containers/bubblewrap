#pragma once

#include "destinations-graph.h"

// --------------------------------------------------------------------------------------------------------------------
// Regular methods of DestinationsGraph

DestinationsGraph *
DestinationsGraph_create (void)
{
  DestinationsGraph *self = malloc (sizeof (DestinationsGraph));

  // Create initial root node.
  // It's a little special because it has no path_part.
  // Also, by default it's not mount point.
  // But things can change later if we bind mount something to the root.
  DestinationsGraph_Node *root = DestinationsGraph_Node_create ();

  self->root = root;
  self->count_mount_points = 0;
  self->count_nodes = 1;
  self->_euler_tour_timer = 0;

  return self;
}

void
DestinationsGraph_free (DestinationsGraph *self)
{
  if (self->nodev != NULL)
    SumSegmentTree_free (self->nodev);

  if (self->readonly != NULL)
    SumSegmentTree_free (self->readonly);

  DestinationsGraph_Node__free_recursive__ (self->root);
  self->_euler_tour_timer = 0;

  free(self);
}

DestinationsGraph_Node *
DestinationsGraph_ensure_mount_point (DestinationsGraph *self, char **destination_path, bool *added)
{
  // We duplicate given destination_path because next
  // we will split it by "/" with strtok function.
  // We don'value want to corrupt original data
  char *destination_path_dup = strdup (*destination_path);

  // Start with root
  DestinationsGraph_Node *current = self->root;

  // Destination_path_dup + 1 means we ignore first "/" in path
  char *next_path_part = strtok (destination_path_dup + 1, "/");

  // We take path_parts one by one
  while (next_path_part != NULL)
    {

      // Look for next node corresponding this next_path_part
      DestinationsGraph_Node *next = DestinationsLinkedList_find_by_path_part (current->children, next_path_part);

      // If we found none, need to create it
      if (next == NULL)
        {
          DestinationsGraph_Node *new_node = DestinationsGraph_Node_create ();
          new_node->path_part = strdup (next_path_part);

          DestinationsLinkedList_push_back (current->children, new_node);
          self->count_nodes++;

          if(added != NULL) *added = TRUE;
          next = new_node;
        }

      current = next;
      next_path_part = strtok (NULL, "/");
    }

  // For now current node is a mount point. Label it
  if (!current->is_mount_point)
    {
      if(added != NULL) *added = TRUE;
      current->is_mount_point = TRUE;
      self->count_mount_points++;
    }

  free (destination_path_dup);
  return current;
}

void
DestinationsGraph__euler_tour__ (DestinationsGraph *self)
{
  self->_euler_tour_timer = 0;
  DestinationsGraph_Node__euler_tour__ (self, self->root);
}

void
DestinationsGraph_debug_pretty_print (DestinationsGraph *self, FILE *fd)
{
  DestinationsGraph_Node_debug_pretty_print (fd, self->root, 0);
}

// ---------------------------------------------------------------------------------------------------------------------
// Flags-related methods of DestinationsGraph

void
DestinationsGraph_Flags_init (DestinationsGraph *self)
{
  // Perform euler tour to reflect nodes on segment tree
  DestinationsGraph__euler_tour__ (self);

  self->nodev = SumSegmentTree_create (self->count_nodes);
  self->readonly = SumSegmentTree_create (self->count_nodes);
}

void
DestinationsGraph_Flags__set_flag__ (SumSegmentTree *segment_tree, DestinationsGraph_Node *node)
{
  SumSegmentTree_modify (segment_tree, node->euler_tour_start, node->euler_tour_end, 1);
}

void
DestinationsGraph_Flags__unset_flag__ (SumSegmentTree *segment_tree, DestinationsGraph_Node *node)
{
  SumSegmentTree_modify (segment_tree, node->euler_tour_start, node->euler_tour_end, 0);
}

bool
DestinationsGraph_Flags__check_flag__ (SumSegmentTree *segment_tree, DestinationsGraph_Node *node)
{
  return SumSegmentTree_query (segment_tree, node->euler_tour_start);
}

void
DestinationsGraph_Flags_set_readonly (DestinationsGraph *self, DestinationsGraph_Node *node)
{
  DestinationsGraph_Flags__set_flag__ (self->readonly, node);
}

void
DestinationsGraph_Flags_unset_readonly (DestinationsGraph *self, DestinationsGraph_Node *node)
{
  DestinationsGraph_Flags__unset_flag__ (self->readonly, node);
}

bool
DestinationsGraph_Flags_check_readonly (DestinationsGraph *self, DestinationsGraph_Node *node)
{
  return DestinationsGraph_Flags__check_flag__ (self->readonly, node);
}

void
DestinationsGraph_Flags_set_nodev (DestinationsGraph *self, DestinationsGraph_Node *node)
{
  DestinationsGraph_Flags__set_flag__ (self->nodev, node);
}

void
DestinationsGraph_Flags_unset_nodev (DestinationsGraph *self, DestinationsGraph_Node *node)
{
  DestinationsGraph_Flags__unset_flag__ (self->nodev, node);
}

bool
DestinationsGraph_Flags_check_nodev (DestinationsGraph *self, DestinationsGraph_Node *node)
{
  return DestinationsGraph_Flags__check_flag__ (self->nodev, node);
}