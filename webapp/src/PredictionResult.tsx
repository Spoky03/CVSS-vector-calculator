import { Button } from "./components/ui/button";

export const PredictionResult = ({
  responseData,
  setLoading,
  setResponseData,
}: {
  responseData: {
    description: string;
    cvss_flags: Record<string, string | number | boolean>;
  } | null;
  setLoading: (loading: boolean) => void;
  setResponseData: (
    data: {
      description: string;
      cvss_flags: Record<string, string | number | boolean>;
    } | null
  ) => void;
}) => {
  if (!responseData) {
    return (
      <div className="text-center text-gray-500">
        No prediction data available.
      </div>
    );
  }

  const getValueColor = (value: string) => {
    const val = value.toUpperCase();
    switch (val) {
      case "H":
        return "bg-red-100 text-red-800 border-red-200";
      case "L":
        return "bg-green-100 text-green-800 border-green-200";
      case "M":
        return "bg-yellow-100 text-yellow-800 border-yellow-200";
      case "N":
        return "bg-gray-100 text-gray-800 border-gray-200";
      case "A":
        return "bg-orange-100 text-orange-800 border-orange-200";
      case "P":
        return "bg-purple-100 text-purple-800 border-purple-200";
      case "R":
        return "bg-blue-100 text-blue-800 border-blue-200";
      default:
        return "bg-gray-100 text-gray-800 border-gray-200";
    }
  };

  const getValueDescription = (metric: string, value: string) => {
    const descriptions: Record<string, Record<string, string>> = {
      AV: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
      AC: { L: "Low", H: "High" },
      PR: { N: "None", L: "Low", H: "High" },
      UI: { N: "None", R: "Required" },
      VC: { N: "None", L: "Low", H: "High" },
      VI: { N: "None", L: "Low", H: "High" },
      VA: { N: "None", L: "Low", H: "High" },
      SC: { N: "None", L: "Low", H: "High" },
      SI: { N: "None", L: "Low", H: "High" },
      SA: { N: "None", L: "Low", H: "High" },
    };
    return descriptions[metric]?.[value.toUpperCase()] || value;
  };

    const handleReset = () => {
    if (setLoading && setResponseData) {
      setLoading(false);
      setResponseData(null);
    }
  };

  return (
    <div className="text-center">
      <h2 className="text-xl font-semibold mb-4 text-gray-800">
        Prediction Result
      </h2>
      <p className="mb-4 text-gray-600">{responseData.description}</p>

      {/* Desktop horizontal table */}
      <div className="hidden md:block overflow-x-auto">
        <table className="w-full border-collapse border border-gray-300 bg-white shadow-sm rounded-lg">
          <thead>
            <tr className="bg-gray-50">
              {Object.keys(responseData.cvss_flags).map((metric) => (
                <th
                  key={metric}
                  className="border border-gray-300 px-3 py-2 text-sm font-semibold text-gray-700"
                >
                  {metric}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            <tr>
              {Object.entries(responseData.cvss_flags).map(
                ([metric, value]) => (
                  <td key={metric} className="border border-gray-300 px-3 py-2">
                    <div className="flex flex-col items-center gap-1">
                      <span
                        className={`px-2 py-1 rounded-full text-xs font-medium border ${getValueColor(
                          String(value)
                        )}`}
                      >
                        {String(value)}
                      </span>
                      <span className="text-xs text-gray-500">
                        {getValueDescription(metric, String(value))}
                      </span>
                    </div>
                  </td>
                )
              )}
            </tr>
          </tbody>
        </table>
      </div>

      {/* Mobile vertical table */}
      <div className="md:hidden">
        <table className="w-full border-collapse border border-gray-300 bg-white shadow-sm rounded-lg">
          <tbody>
            {Object.entries(responseData.cvss_flags).map(([metric, value]) => (
              <tr key={metric}>
                <td className="border border-gray-300 px-3 py-2 bg-gray-50 font-semibold text-gray-700 text-sm w-1/3">
                  {metric}
                </td>
                <td className="border border-gray-300 px-3 py-2">
                  <div className="flex items-center justify-center gap-2">
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium border ${getValueColor(
                        String(value)
                      )}`}
                    >
                      {String(value)}
                    </span>
                    <span className="text-xs text-gray-500">
                      {getValueDescription(metric, String(value))}
                    </span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {/* reset button */}
      <Button
        type="submit"
        className="mt-4"
        onClick={handleReset}
      >
        Reset
      </Button>
    </div>
  );
};
