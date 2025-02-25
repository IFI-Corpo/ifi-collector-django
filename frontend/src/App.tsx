import React, { Suspense, lazy, useContext, useState, useEffect } from "react";
import { Routes, Route, useLocation } from "react-router-dom";
import { ErrorBoundary } from "react-error-boundary";
import SmoothScroller from "./components/SmoothScroller";
import Navbar from "./components/Navbar";
import { ThemeContext, ThemeProvider } from "./context/ThemeContext";
import "ldrs/quantum";

// Error fallback component
function ErrorFallback({ error }: { error: Error }) {
  return (
    <div role="alert">
      <p>Something went wrong:</p>
      <pre style={{ color: "red" }}>{error.message}</pre>
    </div>
  );
}

// Lazy-load pages with error handling
const Home = lazy(() => import("./pages/Home"));
const About = lazy(() => import("./pages/About"));
const Search = lazy(() => import("./pages/Search"));
const CardDetail = lazy(() => import("./pages/CardDetail"));
const Admin = lazy(() => import("./pages/admin"));
const NotFound = lazy(() => import("./pages/NotFound"));
const SignUp = lazy(() =>
  import("@/pages/Signup").catch((error) => {
    console.error("Failed to load SignUp component:", error);
    return { default: () => <div>Failed to load SignUp component.</div> };
  }),
);

const App: React.FC = () => (
  <ThemeProvider>
    <MainApp />
  </ThemeProvider>
);

const MainApp: React.FC = () => {
  const themeContext = useContext(ThemeContext);
  if (!themeContext) return null;

  const { darkMode } = themeContext;
  const loaderColor = darkMode ? "white" : "black";

  const location = useLocation();
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    const timer = setTimeout(() => setLoading(false), 500);
    return () => clearTimeout(timer);
  }, [location]);

  return (
    <div className="app-container">
      <SmoothScroller />
      <Navbar />
      {loading ? (
        <div className="flex flex-col items-center justify-center h-[80vh]">
          <l-quantum size="45" speed="1.75" color={loaderColor}></l-quantum>
        </div>
      ) : (
        <ErrorBoundary FallbackComponent={ErrorFallback}>
          <Suspense fallback={<div>Loading...</div>}>
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/admin" element={<Admin />} />
              <Route path="/about" element={<About />} />
              <Route path="/search" element={<Search />} />
              <Route path="/detail" element={<CardDetail />} />
              <Route path="/signup" element={<SignUp />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </ErrorBoundary>
      )}
    </div>
  );
};

export default App;
