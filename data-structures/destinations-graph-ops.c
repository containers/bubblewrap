#include "destinations-graph.h"

/// --------------------------------------------------------------------------------------------------------------------
/// Safety

void
cleanup_destinations_graphp (void *p)
{
  void **pp = (void **) p;
  if (*pp)
    DestinationsGraph_free ((DestinationsGraph *) *pp);
}

void
cleanup_destinations_graph_nodep (void *p)
{
  void **pp = (void **) p;
  if (*pp)
    DestinationsGraph_Node_free((DestinationsGraph_Node *) *pp);
}

void
cleanup_destinations_graph_node_recursivep (void *p)
{
  void **pp = (void **) p;
  if (*pp)
    DestinationsGraph_Node_free_recursive ((DestinationsGraph_Node *) *pp);
}

// --------------------------------------------------------------------------------------------------------------------
// Regular methods of DestinationsGraph

DestinationsGraph *
DestinationsGraph_create (void)
{
  DestinationsGraph *self = xcalloc(1, sizeof (DestinationsGraph));

  // Create initial root node.
  // It's a little special because it has no path_part.
  // Also, by default it's not mount point.
  // But things can change later if we bind mount something to the root.
  DestinationsGraph_Node *root = DestinationsGraph_Node_create ();

  self->root = root;
  self->count_mount_points = 0;
  self->count_nodes = 1;

  return self;
}

void
DestinationsGraph_free (DestinationsGraph *self)
{
  if (self->nodev != NULL)
    free (self->nodev);

  if (self->readonly != NULL)
    free (self->readonly);

  if(self->root != NULL)
    DestinationsGraph_Node_free_recursive (self->root);

  free(self);
}

DestinationsGraph_Node *
DestinationsGraph_ensure_mount_point (DestinationsGraph *self, char **destination_path, bool *added)
{
  // We duplicate given destination_path because next
  // we will split it by "/" with strtok function.
  // We don'value want to corrupt original data
  char *destination_path_dup = xstrdup (*destination_path);

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
          new_node->path_part = xstrdup (next_path_part);

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

size_t
DestinationsGraph__euler_tour__ (DestinationsGraph *self)
{
  size_t euler_tour_timer = 0;
  DestinationsGraph_Node__euler_tour__ (self->root, &euler_tour_timer);
  return euler_tour_timer;
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
  size_t max_label = DestinationsGraph__euler_tour__ (self);

  self->nodev = xcalloc(max_label, sizeof (bool));
  self->readonly = xcalloc(max_label, sizeof (bool));
}

void
DestinationsGraph_Flags__set_flag__ (bool **flags, DestinationsGraph_Node *node, bool value)
{
  memset (*flags + node->euler_tour_start, value, node->euler_tour_end - node->euler_tour_start);
}

bool
DestinationsGraph_Flags__check_flag__ (bool **flags, DestinationsGraph_Node *node)
{
  return (*flags)[node->euler_tour_start];
}

void
DestinationsGraph_Flags_set_readonly (DestinationsGraph *self, DestinationsGraph_Node *node, bool value)
{
  DestinationsGraph_Flags__set_flag__ (&self->readonly, node, value);
}

bool
DestinationsGraph_Flags_check_readonly (DestinationsGraph *self, DestinationsGraph_Node *node)
{
  return DestinationsGraph_Flags__check_flag__ (&self->readonly, node);
}

void
DestinationsGraph_Flags_set_nodev (DestinationsGraph *self, DestinationsGraph_Node *node, bool value)
{
  DestinationsGraph_Flags__set_flag__ (&self->nodev, node, value);
}

bool
DestinationsGraph_Flags_check_nodev (DestinationsGraph *self, DestinationsGraph_Node *node)
{
  return DestinationsGraph_Flags__check_flag__ (&self->nodev, node);
}