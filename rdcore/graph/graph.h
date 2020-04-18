#pragma once

#include <rdapi/graph/graph.h>
#include <vector>
#include "../object.h"

class Graph: public Object
{
    public:
        Graph() = default;
        void setRoot(RDGraphNode n);
        void removeEdge(const RDGraphEdge* e);
        void removeNode(RDGraphNode n);
        void pushEdge(RDGraphNode source, RDGraphNode target);
        RDGraphNode pushNode();

    public:
        bool empty() const;
        bool containsEdge(RDGraphNode source, RDGraphNode target) const;
        const RDGraphEdge* edge(RDGraphNode source, RDGraphNode target) const;
        size_t outgoing(RDGraphNode n, const RDGraphEdge** edges) const;
        size_t incoming(RDGraphNode n, const RDGraphEdge** edges) const;
        size_t nodes(const RDGraphNode** nodes) const;
        size_t edges(const RDGraphEdge** edges) const;
        RDGraphNode root() const;

    private:
        void removeEdges(RDGraphNode n);

    private:
        mutable std::vector<RDGraphEdge> m_incomings, m_outgoings;

    protected:
        std::vector<RDGraphEdge> m_edges;
        std::vector<RDGraphNode> m_nodes;
        size_t m_nodeid{0};
        RDGraphNode m_root{0};
};
