import React, { useState } from 'react';
import {
  CheckSquare,
  Plus,
  Trash2,
  Clock,
  User,
  Sparkles,
  X,
  RefreshCw,
  CheckCircle2,
  Circle,
} from 'lucide-react';
import type { CaseTask, CaseTaskCreatePayload } from '../../types/case';
import { caseService } from '../../services/caseService';

interface CaseTasksSectionProps {
  caseId: string;
  tasks: CaseTask[];
  onTasksUpdated: () => void;
  showToast: (msg: string) => void;
}

const PRIORITY_BADGES: Record<string, string> = {
  CRITICAL: 'bg-danger-surface text-danger border-danger-border font-bold',
  HIGH: 'bg-warning-surface text-warning border-warning-border font-medium',
  MEDIUM: 'bg-surface-secondary text-foreground border-border',
  LOW: 'bg-surface-secondary text-foreground-muted border-border',
};

export const CaseTasksSection: React.FC<CaseTasksSectionProps> = ({
  caseId,
  tasks,
  onTasksUpdated,
  showToast,
}) => {
  const [showAddModal, setShowAddModal] = useState(false);
  const [taskTitle, setTaskTitle] = useState('');
  const [taskDescription, setTaskDescription] = useState('');
  const [taskPriority, setTaskPriority] = useState<string>('HIGH');
  const [taskAssignee, setTaskAssignee] = useState('');
  const [taskDueDate, setTaskDueDate] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [updatingTaskId, setUpdatingTaskId] = useState<string | null>(null);

  const handleToggleTaskStatus = async (task: CaseTask) => {
    setUpdatingTaskId(task.id);
    const newStatus = task.status === 'COMPLETED' ? 'TODO' : 'COMPLETED';
    try {
      await caseService.updateTask(caseId, task.id, { status: newStatus });
      showToast(newStatus === 'COMPLETED' ? `Task completed: "${task.title}"` : 'Task reopened');
      onTasksUpdated();
    } catch (err: any) {
      alert(`Failed to update task: ${err.message}`);
    } finally {
      setUpdatingTaskId(null);
    }
  };

  const handleDeleteTask = async (taskId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm('Delete this task?')) return;
    try {
      await caseService.deleteTask(caseId, taskId);
      showToast('Task removed from case');
      onTasksUpdated();
    } catch (err: any) {
      alert(`Failed to delete task: ${err.message}`);
    }
  };

  const handleCreateTask = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!taskTitle.trim()) return;

    setSubmitting(true);
    try {
      const payload: CaseTaskCreatePayload = {
        title: taskTitle.trim(),
        description: taskDescription.trim() || undefined,
        priority: taskPriority,
        assignee_id: taskAssignee.trim() || undefined,
        due_at: taskDueDate ? new Date(taskDueDate).toISOString() : undefined,
      };
      await caseService.createTask(caseId, payload);
      setShowAddModal(false);
      setTaskTitle('');
      setTaskDescription('');
      setTaskAssignee('');
      setTaskDueDate('');
      showToast('Task added to case checklist');
      onTasksUpdated();
    } catch (err: any) {
      alert(`Failed to create task: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const completedCount = tasks.filter(t => t.status === 'COMPLETED').length;

  return (
    <div className="bg-surface rounded-2xl border border-border p-5 space-y-4 shadow-xs">
      <div className="flex items-center justify-between pb-3 border-b border-border">
        <div className="flex items-center space-x-2">
          <CheckSquare className="w-4 h-4 text-primary" />
          <h3 className="text-sm font-bold font-mono text-foreground">
            Operational Response Tasks ({completedCount}/{tasks.length} Completed)
          </h3>
        </div>
        <button
          type="button"
          onClick={() => setShowAddModal(true)}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-all cursor-pointer shadow-xs"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Add Task</span>
        </button>
      </div>

      {tasks.length === 0 ? (
        <div className="text-center py-8 space-y-2">
          <p className="text-xs font-mono text-foreground-muted">No operational tasks assigned to this case yet.</p>
          <p className="text-[11px] font-mono text-foreground-muted/80">
            Create checklist tasks for mailbox purges, credential resets, forensic memory captures, or tenant audits.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {tasks.map(task => {
            const isCompleted = task.status === 'COMPLETED';
            const priorityBadge = PRIORITY_BADGES[(task.priority || 'MEDIUM').toUpperCase()] || PRIORITY_BADGES.MEDIUM;

            return (
              <div
                key={task.id}
                className={`p-3.5 rounded-xl border transition-colors flex items-start justify-between gap-3 ${
                  isCompleted
                    ? 'bg-surface-secondary/40 border-border opacity-75'
                    : 'bg-surface border-border hover:border-primary/40'
                }`}
              >
                <div className="flex items-start space-x-3 flex-1 min-w-0">
                  <button
                    type="button"
                    onClick={() => handleToggleTaskStatus(task)}
                    disabled={updatingTaskId === task.id}
                    className="mt-0.5 text-foreground-muted hover:text-primary transition-colors cursor-pointer shrink-0"
                    title={isCompleted ? 'Mark as Incomplete' : 'Mark as Completed'}
                  >
                    {updatingTaskId === task.id ? (
                      <RefreshCw className="w-4 h-4 text-primary animate-spin" />
                    ) : isCompleted ? (
                      <CheckCircle2 className="w-4 h-4 text-success" />
                    ) : (
                      <Circle className="w-4 h-4 text-foreground-muted" />
                    )}
                  </button>

                  <div className="space-y-1 flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`text-xs font-mono font-semibold ${
                          isCompleted ? 'line-through text-foreground-muted' : 'text-foreground'
                        }`}
                      >
                        {task.title}
                      </span>

                      <span className={`px-2 py-0.2 rounded text-[10px] font-mono border ${priorityBadge}`}>
                        {task.priority}
                      </span>

                      {task.is_automated_recommendation && (
                        <span className="px-2 py-0.2 rounded text-[10px] font-mono bg-primary-subtle text-primary border border-primary/30 flex items-center space-x-1">
                          <Sparkles className="w-2.5 h-2.5" />
                          <span>Investigation Gap Action</span>
                        </span>
                      )}
                    </div>

                    {task.description && (
                      <p className="text-[11px] font-mono text-foreground-muted leading-relaxed">
                        {task.description}
                      </p>
                    )}

                    <div className="flex flex-wrap items-center gap-3 text-[10px] font-mono text-foreground-muted pt-1">
                      {task.assignee_id && (
                        <span className="flex items-center space-x-1">
                          <User className="w-3 h-3 text-foreground-muted" />
                          <span>Assignee: {task.assignee_id}</span>
                        </span>
                      )}
                      {task.due_at && (
                        <span className="flex items-center space-x-1">
                          <Clock className="w-3 h-3 text-warning" />
                          <span>Due: {new Date(task.due_at).toLocaleDateString()}</span>
                        </span>
                      )}
                      {isCompleted && task.completed_at && (
                        <span className="text-success">
                          Completed on {new Date(task.completed_at).toLocaleDateString()} by {task.completed_by || 'SOC'}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={e => handleDeleteTask(task.id, e)}
                  className="text-foreground-muted hover:text-danger p-1 transition-colors cursor-pointer shrink-0"
                  title="Delete Task"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            );
          })}
        </div>
      )}

      {/* ADD TASK MODAL */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-surface border border-border rounded-xl shadow-xl w-full max-w-md overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border bg-surface-secondary/40">
              <div className="flex items-center space-x-2">
                <CheckSquare className="w-4 h-4 text-primary" />
                <h3 className="font-mono text-sm font-bold text-foreground">Add Operational Task</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateTask} className="p-5 space-y-4">
              <div>
                <label className="block text-xs font-mono font-medium text-foreground mb-1">
                  Task Title *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Isolate compromised host Host-042 from network"
                  value={taskTitle}
                  onChange={e => setTaskTitle(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                />
              </div>

              <div>
                <label className="block text-xs font-mono font-medium text-foreground mb-1">
                  Description / Action Steps
                </label>
                <textarea
                  rows={2}
                  placeholder="Specific remediation instructions and verification criteria..."
                  value={taskDescription}
                  onChange={e => setTaskDescription(e.target.value)}
                  className="w-full px-3 py-2 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono font-medium text-foreground mb-1">
                    Priority
                  </label>
                  <select
                    value={taskPriority}
                    onChange={e => setTaskPriority(e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                  >
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono font-medium text-foreground mb-1">
                    Assignee
                  </label>
                  <input
                    type="text"
                    placeholder="analyst.mark"
                    value={taskAssignee}
                    onChange={e => setTaskAssignee(e.target.value)}
                    className="w-full px-3 py-1.5 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono font-medium text-foreground mb-1">
                  Due Deadline (Optional)
                </label>
                <input
                  type="date"
                  value={taskDueDate}
                  onChange={e => setTaskDueDate(e.target.value)}
                  className="w-full px-3 py-1.5 bg-surface-secondary rounded-lg border border-border text-xs font-mono text-foreground focus:outline-none focus:border-primary"
                />
              </div>

              <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3.5 py-1.5 rounded-lg border border-border text-xs font-mono text-foreground-muted hover:text-foreground cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold disabled:opacity-50 cursor-pointer"
                >
                  {submitting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>{submitting ? 'Creating...' : 'Create Task'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
