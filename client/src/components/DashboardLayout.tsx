import { useAuth } from "@/_core/hooks/useAuth";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { Sidebar, SidebarContent, SidebarFooter, SidebarHeader, SidebarInset, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { startLogin } from "@/const";
import { useIsMobile } from "@/hooks/useMobile";
import { BrainCircuit, Database, Gauge, LayoutDashboard, LogOut, PanelLeft, Radar, UploadCloud } from "lucide-react";
import { CSSProperties, useEffect, useRef, useState } from "react";
import { useLocation } from "wouter";
import { DashboardLayoutSkeleton } from "./DashboardLayoutSkeleton";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "./ui/dropdown-menu";

const menuItems = [
  { icon: LayoutDashboard, label: "态势总览", path: "/" },
  { icon: UploadCloud, label: "PCAP 上传", path: "/upload" },
  { icon: Database, label: "数据集管理", path: "/datasets" },
  { icon: BrainCircuit, label: "模型训练", path: "/training" },
  { icon: Gauge, label: "模型版本", path: "/models" },
  { icon: Radar, label: "检测分析", path: "/detections" },
];
const SIDEBAR_WIDTH_KEY = "trafficguard-sidebar-width";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const [sidebarWidth, setSidebarWidth] = useState(() => Number(localStorage.getItem(SIDEBAR_WIDTH_KEY)) || 272);
  const { loading, user } = useAuth();
  useEffect(() => localStorage.setItem(SIDEBAR_WIDTH_KEY, `${sidebarWidth}`), [sidebarWidth]);
  if (loading) return <DashboardLayoutSkeleton />;
  if (!user) {
    return <div className="min-h-screen grid place-items-center bg-[#07111f] px-5"><div className="w-full max-w-md rounded-3xl border border-white/10 bg-white/[0.04] p-9 text-center shadow-2xl"><div className="mx-auto mb-5 grid h-14 w-14 place-items-center rounded-2xl bg-cyan-400 text-slate-950"><Radar className="h-7 w-7" /></div><h1 className="text-2xl font-semibold text-white">进入 TrafficGuard</h1><p className="mt-3 text-sm leading-6 text-slate-400">登录后即可管理 PCAP 数据集、模型版本和离线检测任务。</p><Button onClick={() => startLogin()} className="mt-7 w-full bg-cyan-300 text-slate-950 hover:bg-cyan-200">登录平台</Button></div></div>;
  }
  return <SidebarProvider style={{ "--sidebar-width": `${sidebarWidth}px` } as CSSProperties}><LayoutContent setSidebarWidth={setSidebarWidth}>{children}</LayoutContent></SidebarProvider>;
}

function LayoutContent({ children, setSidebarWidth }: { children: React.ReactNode; setSidebarWidth: (width: number) => void }) {
  const { user, logout } = useAuth();
  const [location, setLocation] = useLocation();
  const [resizing, setResizing] = useState(false);
  const sidebarRef = useRef<HTMLDivElement>(null);
  const mobile = useIsMobile();
  const active = menuItems.find(item => item.path === location) ?? menuItems[0];
  useEffect(() => {
    const move = (event: MouseEvent) => { if (!resizing) return; const left = sidebarRef.current?.getBoundingClientRect().left ?? 0; const next = event.clientX - left; if (next >= 220 && next <= 360) setSidebarWidth(next); };
    const stop = () => setResizing(false);
    window.addEventListener("mousemove", move); window.addEventListener("mouseup", stop);
    return () => { window.removeEventListener("mousemove", move); window.removeEventListener("mouseup", stop); };
  }, [resizing, setSidebarWidth]);
  return <>
    <div ref={sidebarRef} className="relative">
      <Sidebar collapsible="icon" className="border-r border-white/[0.08] bg-[#091525] text-slate-200">
        <SidebarHeader className="h-[76px] border-b border-white/[0.07] px-4">
          <div className="flex h-full items-center gap-3"><div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-cyan-300 text-slate-950 shadow-[0_0_24px_rgba(103,232,249,.2)]"><Radar className="h-5 w-5" /></div><div className="min-w-0 group-data-[collapsible=icon]:hidden"><p className="text-sm font-semibold tracking-wide text-white">TRAFFICGUARD</p><p className="text-[10px] uppercase tracking-[0.2em] text-cyan-300/80">ML security lab</p></div></div>
        </SidebarHeader>
        <SidebarContent className="px-3 py-5"><p className="mb-2 px-2 text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500 group-data-[collapsible=icon]:hidden">工作台</p><SidebarMenu>{menuItems.map(item => <SidebarMenuItem key={item.path}><SidebarMenuButton isActive={location === item.path} onClick={() => setLocation(item.path)} tooltip={item.label} className="h-11 rounded-xl text-slate-400 hover:bg-white/[0.06] hover:text-white data-[active=true]:bg-cyan-300 data-[active=true]:text-slate-950 data-[active=true]:font-medium"><item.icon className="h-4.5 w-4.5" /><span>{item.label}</span></SidebarMenuButton></SidebarMenuItem>)}</SidebarMenu></SidebarContent>
        <SidebarFooter className="border-t border-white/[0.07] p-3"><DropdownMenu><DropdownMenuTrigger asChild><button className="flex w-full items-center gap-3 rounded-xl p-2 text-left hover:bg-white/[0.06]"><Avatar className="h-8 w-8 border border-white/10"><AvatarFallback className="bg-slate-800 text-xs text-cyan-200">{user?.name?.charAt(0).toUpperCase() ?? "U"}</AvatarFallback></Avatar><div className="min-w-0 flex-1 group-data-[collapsible=icon]:hidden"><p className="truncate text-xs font-medium text-slate-200">{user?.name ?? "安全分析员"}</p><p className="mt-0.5 truncate text-[11px] text-slate-500">已认证会话</p></div></button></DropdownMenuTrigger><DropdownMenuContent align="end"><DropdownMenuItem className="text-destructive" onClick={logout}><LogOut className="mr-2 h-4 w-4" />退出登录</DropdownMenuItem></DropdownMenuContent></DropdownMenu></SidebarFooter>
      </Sidebar>
      <div aria-hidden className="absolute inset-y-0 right-0 w-1 cursor-col-resize hover:bg-cyan-300/30" onMouseDown={() => setResizing(true)} />
    </div>
    <SidebarInset className="bg-[#07111f] text-slate-100">{mobile && <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-white/[0.08] bg-[#091525]/90 px-4 backdrop-blur"><SidebarTrigger /><span className="text-sm font-medium">{active.label}</span></header>}<main className="min-h-screen p-4 md:p-7">{children}</main></SidebarInset>
  </>;
}
