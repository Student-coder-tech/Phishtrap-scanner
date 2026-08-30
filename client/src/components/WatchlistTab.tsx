import React, { useState } from 'react';
import {
  BookmarkCheck,
  Plus,
  Trash2,
  CheckCircle2,
  XCircle,
  Search,
  Building2,
  Globe,
  AlertCircle,
  X,
  Check
} from 'lucide-react';
import { WatchlistBrand } from '../types';
import { api, ApiError } from '../services/api';

interface WatchlistTabProps {
  watchlist: WatchlistBrand[];
  isLoading: boolean;
  onRefresh: () => void;
}

const CATEGORIES = [
  'Banking',
  'Cloud & SaaS',
  'Crypto & FinTech',
  'E-commerce',
  'Social Media',
  'Government',
  'Other',
];

export const WatchlistTab: React.FC<WatchlistTabProps> = ({
  watchlist,
  isLoading,
  onRefresh,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [showAddModal, setShowAddModal] = useState(false);

  // Form state
  const [newName, setNewName] = useState('');
  const [newDomain, setNewDomain] = useState('');
  const [newCategory, setNewCategory] = useState('Banking');
  const [formError, setFormError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleToggle = async (brand: WatchlistBrand) => {
    try {
      const targetId = brand.id || brand._id;
      if (!targetId) return;
      await api.toggleWatchlistBrand(targetId, !brand.active);
      onRefresh();
    } catch (err: any) {
      alert(`Failed to update status: ${err.message}`);
    }
  };

  const handleDelete = async (brand: WatchlistBrand) => {
    const targetId = brand.id || brand._id;
    if (!targetId) return;
    if (!window.confirm(`Are you sure you want to remove ${brand.name} from the active watchlist?`)) {
      return;
    }

    try {
      await api.deleteWatchlistBrand(targetId);
      onRefresh();
    } catch (err: any) {
      alert(`Failed to delete brand: ${err.message}`);
    }
  };

  const handleAddBrand = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim()) {
      setFormError('Please enter a brand name.');
      return;
    }
    if (!newDomain.trim()) {
      setFormError('Please enter the official domain.');
      return;
    }

    setFormError(null);
    setIsSubmitting(true);

    try {
      await api.addWatchlistBrand({
        name: newName.trim(),
        domain: newDomain.trim(),
        category: newCategory,
      });

      setNewName('');
      setNewDomain('');
      setShowAddModal(false);
      onRefresh();
    } catch (err: any) {
      setFormError(err.message || 'Failed to add brand.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const filtered = watchlist.filter((b) => {
    const matchesSearch =
      searchTerm === '' ||
      b.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      b.domain.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesCategory = selectedCategory === 'ALL' || b.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  const activeCount = watchlist.filter((b) => b.active).length;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
        <div>
          <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <BookmarkCheck size={18} className="text-purple-500" />
            Monitored Brand Watchlist
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            {activeCount} active protected brands out of {watchlist.length} total monitored entities.
          </p>
        </div>

        <button
          id="add-watchlist-brand-btn"
          onClick={() => {
            setFormError(null);
            setShowAddModal(true);
          }}
          className="flex items-center gap-2 px-4 py-2 text-xs font-mono font-bold rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white shadow-xs shadow-cyan-600/20 transition-all cursor-pointer"
        >
          <Plus size={15} />
          <span>Add Protected Brand</span>
        </button>
      </div>

      {/* Filter and Search Row */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
        <div className="relative w-full sm:w-80">
          <Search className="absolute left-3 top-2.5 text-slate-400" size={15} />
          <input
            type="text"
            placeholder="Search brand name or domain..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-xs font-mono rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500/20"
          />
        </div>

        {/* Category Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto w-full sm:w-auto pb-1 sm:pb-0">
          <button
            onClick={() => setSelectedCategory('ALL')}
            className={`px-3 py-1 text-xs font-mono rounded-lg transition-colors whitespace-nowrap ${
              selectedCategory === 'ALL'
                ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900 font-bold'
                : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200'
            }`}
          >
            All
          </button>
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-2.5 py-1 text-xs font-mono rounded-lg transition-colors whitespace-nowrap ${
                selectedCategory === cat
                  ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900 font-bold'
                  : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Watchlist Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filtered.map((brand) => (
          <div
            key={brand.id || brand._id}
            id={`watchlist-card-${brand.name.toLowerCase().replace(/\s+/g, '-')}`}
            className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col justify-between hover:border-slate-300 dark:hover:border-slate-700 transition-all group"
          >
            <div>
              <div className="flex items-start justify-between gap-3 mb-2.5">
                <div className="flex items-center gap-2.5">
                  <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-500">
                    <Building2 size={18} />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                      {brand.name}
                    </h3>
                    <span className="text-[11px] font-mono text-slate-400">
                      {brand.category}
                    </span>
                  </div>
                </div>

                {/* Active status indicator */}
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase border ${
                    brand.active
                      ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-400 border-slate-300 dark:border-slate-700'
                  }`}
                >
                  {brand.active ? 'ACTIVE' : 'INACTIVE'}
                </span>
              </div>

              {/* Genuine domain */}
              <div className="p-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800/80 my-3">
                <span className="text-[10px] font-mono text-slate-400 block uppercase">
                  Protected Domain:
                </span>
                <span className="text-xs font-mono font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5 mt-0.5">
                  <Globe size={13} className="text-cyan-500" />
                  {brand.domain}
                </span>
              </div>
            </div>

            {/* Action buttons */}
            <div className="flex items-center justify-between pt-3 border-t border-slate-100 dark:border-slate-800/80 mt-2">
              <button
                onClick={() => handleToggle(brand)}
                className={`flex items-center gap-1.5 text-xs font-mono font-semibold px-2.5 py-1 rounded-lg transition-colors cursor-pointer ${
                  brand.active
                    ? 'text-amber-600 dark:text-amber-400 hover:bg-amber-500/10'
                    : 'text-emerald-600 dark:text-emerald-400 hover:bg-emerald-500/10'
                }`}
              >
                {brand.active ? <XCircle size={14} /> : <CheckCircle2 size={14} />}
                <span>{brand.active ? 'Deactivate' : 'Activate'}</span>
              </button>

              <button
                onClick={() => handleDelete(brand)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-rose-500 hover:bg-rose-500/10 transition-colors cursor-pointer"
                title="Remove brand from watchlist"
              >
                <Trash2 size={15} />
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Add Brand Modal */}
      {showAddModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-xs"
          onClick={() => setShowAddModal(false)}
        >
          <div
            className="w-full max-w-md p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-100 dark:border-slate-800">
              <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Plus size={18} className="text-cyan-500" />
                Add Brand to Watchlist
              </h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleAddBrand} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-slate-700 dark:text-slate-300 block mb-1">
                  Brand Name *
                </label>
                <input
                  type="text"
                  placeholder="e.g. Bank of Scotland"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500/20"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-700 dark:text-slate-300 block mb-1">
                  Official Genuine Domain *
                </label>
                <input
                  type="text"
                  placeholder="e.g. bankofscotland.co.uk"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  className="w-full px-3.5 py-2.5 text-xs font-mono rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500/20"
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-700 dark:text-slate-300 block mb-1">
                  Industry Category
                </label>
                <select
                  value={newCategory}
                  onChange={(e) => setNewCategory(e.target.value)}
                  className="w-full px-3.5 py-2.5 text-xs font-mono rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500/20"
                >
                  {CATEGORIES.map((cat) => (
                    <option key={cat} value={cat}>
                      {cat}
                    </option>
                  ))}
                </select>
              </div>

              {formError && (
                <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-400 text-xs flex items-center gap-2">
                  <AlertCircle size={15} className="shrink-0" />
                  <span>{formError}</span>
                </div>
              )}

              <div className="flex items-center justify-end gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 text-xs font-semibold rounded-xl text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-5 py-2 text-xs font-mono font-bold rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50 cursor-pointer shadow-xs"
                >
                  {isSubmitting ? 'Saving...' : 'Add to Watchlist'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
