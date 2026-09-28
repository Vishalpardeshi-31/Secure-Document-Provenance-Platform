import { request } from './api';
import {
  InvestigationCase,
  InvestigationCaseDetail,
  InvestigationEvidence,
  InvestigationResult,
  InvestigationReport,
} from '../types/investigation';

export const investigationService = {
  createCase: async (
    data: { title: string; description?: string; document_id?: string; document_version_id?: string },
    token: string
  ): Promise<InvestigationCase> => {
    return request<InvestigationCase>('/investigations', {
      method: 'POST',
      body: JSON.stringify(data),
      token,
    });
  },

  listCases: async (token: string, limit = 50, offset = 0): Promise<InvestigationCase[]> => {
    return request<InvestigationCase[]>(`/investigations?limit=${limit}&offset=${offset}`, {
      method: 'GET',
      token,
    });
  },

  getCaseDetail: async (caseId: string, token: string): Promise<InvestigationCaseDetail> => {
    return request<InvestigationCaseDetail>(`/investigations/${caseId}`, {
      method: 'GET',
      token,
    });
  },

  uploadEvidence: async (
    caseId: string,
    file: File,
    token: string
  ): Promise<InvestigationEvidence> => {
    const formData = new FormData();
    formData.append('file', file);
    return request<InvestigationEvidence>(`/investigations/${caseId}/evidence`, {
      method: 'POST',
      body: formData,
      token,
    });
  },

  analyzeEvidence: async (
    caseId: string,
    token: string,
    evidenceId?: string
  ): Promise<InvestigationResult> => {
    const query = evidenceId ? `?evidence_id=${evidenceId}` : '';
    return request<InvestigationResult>(`/investigations/${caseId}/analyze${query}`, {
      method: 'POST',
      token,
    });
  },

  exportReport: async (caseId: string, token: string): Promise<InvestigationReport> => {
    return request<InvestigationReport>(`/investigations/${caseId}/report`, {
      method: 'GET',
      token,
    });
  },
};
