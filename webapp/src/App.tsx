import { useState } from "react";
import { DescriptionForm } from "./DescriptionForm";
import { MetricsList } from "./MetricsList";
import { PredictionResult } from "./PredictionResult";
import { Spinner } from "./Spinner";

type ResponseData = {
  description: string;
  cvss_flags: Record<string, string | number | boolean>;
};

function App() {
  const [loading, setLoading] = useState(false);
  const [responseData, setResponseData] = useState<ResponseData | null>(null);
  return (
    <>
      <div className="bg-gray-100 min-h-screen flex flex-col items-center pb-8">
        <header className="mb-8 w-full bg-white shadow-md p-4">
          <h1 className="text-3xl font-bold">CVSS 4.0 Vector Calculator</h1>
        </header>
        <main className="flex flex-col items-center space-y-8 w-full p-1">
          <div className="max-w-2xl xl:w-2xl md:w-xl sm:w-xl mx-auto p-4 bg-white shadow-md rounded-lg">
            {loading ? (
              <>
                <Spinner />
                <div className="text-center text-gray-500">Loading...</div>
              </>
            ) : responseData ? (
              <PredictionResult responseData={responseData} setLoading={setLoading} setResponseData={setResponseData} />
            ) : (
              <>
                <h2 className="text-xl font-semibold">
                  Enter Vulnerability Description
                </h2>
                <p className="text-gray-600">
                  Provide a detailed description of the vulnerability to get
                  CVSS vector predictions.
                </p>
                <DescriptionForm
                  setLoading={setLoading}
                  setResponseData={setResponseData}
                />
              </>
            )}
          </div>
          <div className="max-w-2xl mx-auto p-4 bg-white shadow-md rounded-lg">
            <MetricsList />
          </div>
        </main>
      </div>
      <footer className="bg-gray-800 text-center text-gray-50 p-4">
        <p>Powered by CVSS 4.0</p>
        <p>© 2025 Maciej Suski, Stefan Grzelec, Łukasz Kowalczyk</p>
      </footer>
    </>
  );
}

export default App;
