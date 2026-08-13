import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Sidebar, SidebarContent, SidebarFooter, SidebarHeader, SidebarInset, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { useIsMobile } from "@/hooks/useMobile";
import { Archive, BrainCircuit, Database, Gauge, LayoutDashboard, Radar, Tags, UploadCloud } from "lucide-react";
import { useLocation } from "wouter";

const menuItems = [
  { icon: LayoutDashboard, label: "态势总览", path: "/" },
  { icon: UploadCloud, label: "样本上传", path: "/upload" },
  { icon: Database, label: "数据管理", path: "/datasets" },
  { icon: Tags, label: "标注配置", path: "/annotations" },
  { icon: BrainCircuit, label: "模型训练", path: "/training" },
  { icon: Gauge, label: "模型版本", path: "/models" },
  { icon: Radar, label: "流量检测", path: "/detections" },
  { icon: Archive, label: "历史归档", path: "/history" },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return <SidebarProvider><LayoutContent>{children}</LayoutContent></SidebarProvider>;
}

function LayoutContent({ children }: { children: React.ReactNode }) {
  const [location, setLocation] = useLocation();
  const mobile = useIsMobile();
  const active = menuItems.find(item => item.path === location) ?? menuItems[0];

  return <>
    <Sidebar collapsible="icon" className="border-r border-white/[0.08] bg-[#091525] text-slate-200">
      <SidebarHeader className="h-[76px] border-b border-white/[0.07] px-4">
        <div className="flex h-full items-center gap-3">
          <div className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-cyan-300 text-slate-950 shadow-[0_0_24px_rgba(103,232,249,.2)]"><Radar className="h-5 w-5" /></div>
          <div className="min-w-0 group-data-[collapsible=icon]:hidden"><p className="text-sm font-semibold tracking-wide text-white">TRAFFICGUARD</p><p className="text-[10px] uppercase tracking-[0.2em] text-cyan-300/80">ML security lab</p></div>
        </div>
      </SidebarHeader>
      <SidebarContent className="px-3 py-5">
        <p className="mb-2 px-2 text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500 group-data-[collapsible=icon]:hidden">公共工作区</p>
        <SidebarMenu>{menuItems.map(item => <SidebarMenuItem key={item.path}><SidebarMenuButton isActive={location === item.path} onClick={() => setLocation(item.path)} tooltip={item.label} className="h-11 rounded-xl text-slate-400 hover:bg-white/[0.06] hover:text-white data-[active=true]:bg-cyan-300 data-[active=true]:font-medium data-[active=true]:text-slate-950"><item.icon className="h-4.5 w-4.5" /><span>{item.label}</span></SidebarMenuButton></SidebarMenuItem>)}</SidebarMenu>
      </SidebarContent>
      <SidebarFooter className="border-t border-white/[0.07] p-3"><div className="flex items-center gap-3 rounded-xl p-2"><Avatar className="h-8 w-8 border border-white/10"><AvatarFallback className="bg-slate-800 text-xs text-cyan-200">P</AvatarFallback></Avatar><div className="min-w-0 flex-1 group-data-[collapsible=icon]:hidden"><p className="truncate text-xs font-medium text-slate-200">公共工作区</p><p className="mt-0.5 truncate text-[11px] text-slate-500">无需登录</p></div></div></SidebarFooter>
    </Sidebar>
    <SidebarInset className="bg-[#07111f] text-slate-100">
      {mobile && <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-white/[0.08] bg-[#091525]/90 px-4 backdrop-blur"><SidebarTrigger /><span className="text-sm font-medium">{active.label}</span></header>}
      <main className="min-h-screen p-4 md:p-7">{children}</main>
    </SidebarInset>
  </>;
}
