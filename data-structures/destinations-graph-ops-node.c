#include "destinations-graph.h"

DestinationsGraph_Node *
DestinationsGraph_Node_create (void)
{
  DestinationsGraph_Node *self = malloc (sizeof (DestinationsGraph_Node));

  self->path_part = NULL;
  self->is_mount_point = FALSE;
  self->source = NULL;
  self->dest = NULL;
  self->children = DestinationsLinkedList_create ();
  self->euler_tour_start = 0;
  self->euler_tour_end = 0;

  return self;
}

void
DestinationsGraph_Node_free (DestinationsGraph_Node *self)
{
  self->is_mount_point = 0;
  free (self->path_part = NULL);
  free (self->source);
  free (self->dest);
  DestinationsLinkedList_free (self->children);
  free(self);
}

void
DestinationsGraph_Node__free_recursive__ (DestinationsGraph_Node *self)
{
  DestinationsLinkedList_Node *currentChild = self->children->head;

  while (currentChild != NULL)
    {
      DestinationsGraph_Node__free_recursive__ (currentChild->value);
      currentChild = currentChild->next;
    }

  DestinationsGraph_Node_free (self);
}

void
DestinationsGraph_Node__euler_tour__ (DestinationsGraph *graph, DestinationsGraph_Node *self)
{
  self->euler_tour_start = graph->_euler_tour_timer++;

  DestinationsLinkedList_Node *currentChild = self->children->head;

  while (currentChild != NULL)
    {
      DestinationsGraph_Node__euler_tour__ (graph, currentChild->value);
      currentChild = currentChild->next;
    }

  self->euler_tour_end = graph->_euler_tour_timer++;
}

void
DestinationsGraph_Node_debug_pretty_print (FILE *fd, DestinationsGraph_Node *current, int depth)
{
  for (int i = 0; i < depth; i++)
    fputs ("  |", fd);

  if (depth == 0)
    fprintf (fd, "/ ");
  else
    fprintf (fd, "- %s ", current->path_part);

  if (current->is_mount_point)
    fprintf (fd, "(*) ");

  fprintf (fd, "<==> (%d; %d)", current->euler_tour_start, current->euler_tour_end);

  fprintf (fd, "\n");

  DestinationsLinkedList_Node *currentChild = current->children->head;

  while (currentChild != NULL)
    {
      DestinationsGraph_Node_debug_pretty_print (fd, currentChild->value, depth + 1);
      currentChild = currentChild->next;
    }
}