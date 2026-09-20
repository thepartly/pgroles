import { Callout } from '@/components/Callout'
import {
  PostgresAccessDriftLab,
  PostgresAcmePlayground,
  PostgresCapabilityRolesLab,
  PostgresDefaultPrivilegesLab,
  PostgresGatesLab,
  PostgresMembershipMechanicsLab,
  PostgresOffboardingLab,
  PostgresOwnershipLab,
  PostgresSecurityReviewLab,
} from '@/components/AcmeStoryLabs'
import { OperatorArchitectureDiagram } from '@/components/OperatorArchitectureDiagram'
import { OperatorReconciliationDiagram } from '@/components/OperatorReconciliationDiagram'
import { QuickLink, QuickLinks } from '@/components/QuickLinks'
import { RoleGraphDiagram } from '@/components/RoleGraphDiagram'
import { WorkspaceDataFlowDiagram } from '@/components/WorkspaceDataFlowDiagram'
import { ExplorerScenario } from '@/components/ExplorerScenario'
import { explorerScenarios } from '@/lib/explorerScenarios.mjs'

const tags = {
  'explorer-scenario': {
    selfClosing: true,
    render: ExplorerScenario,
    attributes: { scenario: { type: String, required: true, matches: explorerScenarios.map((scenario) => scenario.id), errorLevel: 'critical' } },
  },
  callout: {
    attributes: {
      title: { type: String },
      type: {
        type: String,
        default: 'note',
        matches: ['note', 'warning', 'beginner'],
        errorLevel: 'critical',
      },
    },
    render: Callout,
  },
  figure: {
    selfClosing: true,
    attributes: {
      src: { type: String },
      alt: { type: String },
      caption: { type: String },
    },
    render: ({ src, alt = '', caption }) => (
      <figure>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={src} alt={alt} />
        <figcaption>{caption}</figcaption>
      </figure>
    ),
  },
  'quick-links': {
    render: QuickLinks,
  },
  'quick-link': {
    selfClosing: true,
    render: QuickLink,
    attributes: {
      title: { type: String },
      description: { type: String },
      icon: { type: String },
      href: { type: String },
    },
  },
  'operator-architecture-diagram': {
    selfClosing: true,
    render: OperatorArchitectureDiagram,
  },
  'operator-reconciliation-diagram': {
    selfClosing: true,
    render: OperatorReconciliationDiagram,
  },
  'postgres-permission-lab': {
    selfClosing: true,
    render: PostgresGatesLab,
  },
  'postgres-capability-roles-lab': {
    selfClosing: true,
    render: PostgresCapabilityRolesLab,
  },
  'postgres-access-drift-lab': {
    selfClosing: true,
    render: PostgresAccessDriftLab,
  },
  'postgres-ownership-lab': {
    selfClosing: true,
    render: PostgresOwnershipLab,
  },
  'postgres-default-privileges-lab': {
    selfClosing: true,
    render: PostgresDefaultPrivilegesLab,
  },
  'postgres-offboarding-lab': {
    selfClosing: true,
    render: PostgresOffboardingLab,
  },
  'postgres-security-review-lab': {
    selfClosing: true,
    render: PostgresSecurityReviewLab,
  },
  'postgres-acme-playground': {
    selfClosing: true,
    render: PostgresAcmePlayground,
  },
  'postgres-role-hierarchy-lab': {
    selfClosing: true,
    render: PostgresMembershipMechanicsLab,
  },
  'role-graph-diagram': {
    selfClosing: true,
    render: RoleGraphDiagram,
  },
  'workspace-data-flow-diagram': {
    selfClosing: true,
    render: WorkspaceDataFlowDiagram,
  },
}

export default tags
