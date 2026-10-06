/**
 * vis-network integration for SAQRIntel network graphs.
 */
/* global vis */

let saqrintelNetwork = null;

function renderNetworkGraph(containerId, graphData) {
  const container = document.getElementById(containerId);
  if (!container || typeof vis === "undefined") return;

  const nodes = new vis.DataSet((graphData.nodes || []).map((n) => ({
    id: n.id,
    label: n.label,
    title: n.title || n.label,
    color: {
      background: n.color || "#7f7f7f",
      border: "#0a1016",
      highlight: { background: n.color || "#7f7f7f", border: "#ffffff" },
    },
    font: { color: "#e7eef6", size: 12 },
    shape: n.group === "port" ? "dot" : n.group === "ip" ? "diamond" : "box",
  })));

  const edges = new vis.DataSet((graphData.edges || []).map((e, i) => ({
    id: i,
    from: e.from,
    to: e.to,
    color: { color: "#3a5168" },
    arrows: "to",
  })));

  const options = {
    physics: {
      enabled: true,
      barnesHut: { gravitationalConstant: -8000, springLength: 120 },
      stabilization: { iterations: 120 },
    },
    interaction: { hover: true, tooltipDelay: 120 },
    edges: { smooth: { type: "dynamic" } },
  };

  if (saqrintelNetwork) {
    saqrintelNetwork.destroy();
  }
  saqrintelNetwork = new vis.Network(container, { nodes, edges }, options);
}

window.renderNetworkGraph = renderNetworkGraph;
