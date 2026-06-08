import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Upload, 
  ListOrdered, 
  ShieldAlert, 
  Settings, 
  FileText,
  Search,
  Activity
} from 'lucide-react';
import { clsx } from 'clsx';

const Sidebar = () => {
  const navItems = [
    { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
    { to: '/upload', icon: Upload, label: 'Upload Sample' },
    { to: '/queue', icon: ListOrdered, label: 'Analysis Queue' },
  ];

  const secondaryItems = [
    { to: '/search', icon: Search, label: 'Search IOCs' },
    { to: '/intelligence', icon: Activity, label: 'Threat Intel' },
    { to: '/reports', icon: FileText, label: 'My Reports' },
  ];

  return (
    <aside className="w-64 bg-dark-900 border-r border-dark-800 flex flex-col h-screen">
      <div className="p-6 flex items-center gap-3">
        <div className="w-10 h-10 bg-primary-600 rounded-lg flex items-center justify-center shadow-lg shadow-primary-900/20">
          <ShieldAlert className="text-white" size={24} />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white">MalLens</h1>
          <p className="text-xs text-dark-400 font-medium uppercase tracking-widest">Analyzer</p>
        </div>
      </div>

      <nav className="flex-1 px-4 py-6 space-y-1">
        <div className="text-xs font-semibold text-dark-500 uppercase tracking-wider px-3 mb-2">Main Menu</div>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) => clsx(
              'flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 group',
              isActive 
                ? 'bg-primary-600/10 text-primary-500 font-medium' 
                : 'text-dark-400 hover:bg-dark-800 hover:text-dark-200'
            )}
          >
            <item.icon size={20} className={clsx(
              'transition-colors',
              'group-hover:text-primary-400'
            )} />
            <span>{item.label}</span>
            {item.label === 'Analysis Queue' && (
              <span className="ml-auto bg-dark-800 text-dark-400 text-[10px] px-1.5 py-0.5 rounded-full border border-dark-700">12</span>
            )}
          </NavLink>
        ))}

        <div className="pt-8 pb-2 text-xs font-semibold text-dark-500 uppercase tracking-wider px-3 mb-2">Insights</div>
        {secondaryItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) => clsx(
              'flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 group',
              isActive 
                ? 'bg-primary-600/10 text-primary-500 font-medium' 
                : 'text-dark-400 hover:bg-dark-800 hover:text-dark-200'
            )}
          >
            <item.icon size={20} className="group-hover:text-primary-400" />
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-dark-800">
        <div className="bg-dark-800/50 rounded-xl p-4 border border-dark-700">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-2 h-2 rounded-full bg-success-500 animate-pulse"></div>
            <span className="text-xs font-medium text-dark-300">System Online</span>
          </div>
          <div className="space-y-2">
            <div className="flex justify-between text-[10px] text-dark-500">
              <span>Analysis Capacity</span>
              <span>85%</span>
            </div>
            <div className="h-1 bg-dark-700 rounded-full overflow-hidden">
              <div className="h-full bg-primary-600 w-[85%]"></div>
            </div>
          </div>
        </div>
        
        <button className="w-full mt-4 flex items-center gap-3 px-3 py-2 text-dark-400 hover:text-dark-200 hover:bg-dark-800 rounded-lg transition-colors">
          <Settings size={20} />
          <span className="text-sm font-medium">Settings</span>
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
