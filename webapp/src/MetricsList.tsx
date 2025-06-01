import { getRequest } from "./lib/requests";
import { useEffect, useState } from "react";
import type {
  MetricInfoWithAbbreviation,
  MetricsResponse,
} from "./lib/interfaces";
export const MetricsList = () => {
  const [metrics, setMetrics] = useState<MetricInfoWithAbbreviation[]>([]);

  useEffect(() => {
    // Fetch metrics from the server
    getRequest("/metrics/all")
      .then((response: { data: MetricsResponse }) => {
        console.log("Metrics response:", response);
        const metricsData = Object.entries(response.data.metrics).map(
          ([key, value]) => ({
            ...value,
            abbreviation: key,
          })
        ) as MetricInfoWithAbbreviation[];
        setMetrics(metricsData);
      })
      .catch((error) => {
        console.error("Error fetching metrics:", error);
        // Handle error
      });
  }, []);
  return (
    <div>
      <strong>Metrics:</strong>{" "}
      {metrics.length > 0 ? (
        <ul>
          {metrics.map((metric) => (
            <li key={metric.abbreviation} className="mr-2">
              <strong>{metric.abbreviation}:</strong> {metric.name} -{" "}
              {metric.description}{" "}
              <span className="text-sm text-gray-500">
                ({metric.values.join(", ")})
              </span>
            </li>
          ))}{" "}
        </ul>
      ) : (
        <span>No metrics available</span>
      )}
    </div>
  );
};
