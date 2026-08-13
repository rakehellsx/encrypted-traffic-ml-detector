import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import DashboardLayout from "./components/DashboardLayout";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import Datasets from "./pages/Datasets";
import Detections from "./pages/Detections";
import Home from "./pages/Home";
import History from "./pages/History";
import Models from "./pages/Models";
import Training from "./pages/Training";
import Upload from "./pages/Upload";
import AnnotationSets from "./pages/AnnotationSets";

function Shell({ children }: { children: React.ReactNode }) { return <DashboardLayout>{children}</DashboardLayout>; }
function Router() { return <Switch><Route path="/"><Shell><Home /></Shell></Route><Route path="/upload"><Shell><Upload /></Shell></Route><Route path="/datasets"><Shell><Datasets /></Shell></Route><Route path="/annotations"><Shell><AnnotationSets /></Shell></Route><Route path="/training"><Shell><Training /></Shell></Route><Route path="/models"><Shell><Models /></Shell></Route><Route path="/detections"><Shell><Detections /></Shell></Route><Route path="/history"><Shell><History /></Shell></Route><Route path="/404" component={NotFound} /><Route component={NotFound} /></Switch>; }
export default function App() { return <ErrorBoundary><ThemeProvider defaultTheme="dark"><TooltipProvider><Toaster theme="dark" richColors position="top-right" /><Router /></TooltipProvider></ThemeProvider></ErrorBoundary>; }
