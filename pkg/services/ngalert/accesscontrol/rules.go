package accesscontrol

import (
	"fmt"
	"strings"
	"strings"

	"golang.org/x/net/context"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/expr"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/dashboards"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/store"
)

const (
	ruleCreate = accesscontrol.ActionAlertingRuleCreate
	ruleRead   = accesscontrol.ActionAlertingRuleRead
	ruleUpdate = accesscontrol.ActionAlertingRuleUpdate
	ruleDelete = accesscontrol.ActionAlertingRuleDelete
)

type RuleService struct {
	genericService
}

func NewRuleService(ac accesscontrol.AccessControl) *RuleService {
	return &RuleService{
		genericService{ac: ac},
	}
}

// getReadFolderAccessEvaluator constructs accesscontrol.Evaluator that checks all permissions required to read rules in  specific folder
func getReadFolderAccessEvaluator(folderUID string) accesscontrol.Evaluator {
	return accesscontrol.EvalAll(
		accesscontrol.EvalPermission(ruleRead, dashboards.ScopeFoldersProvider.GetResourceScopeUID(folderUID)),
		accesscontrol.EvalPermission(dashboards.ActionFoldersRead, dashboards.ScopeFoldersProvider.GetResourceScopeUID(folderUID)),
	)
}

// getRulesReadEvaluator constructs accesscontrol.Evaluator that checks all permissions required to access provided rules
func (r *RuleService) getRulesReadEvaluator(rules ...*models.AlertRule) accesscontrol.Evaluator {
	added := make(map[string]struct{}, 1)
	evals := make([]accesscontrol.Evaluator, 0, 1)
	for _, rule := range rules {
		if _, ok := added[rule.NamespaceUID]; ok {
			continue
		}
		added[rule.NamespaceUID] = struct{}{}
		evals = append(evals, getReadFolderAccessEvaluator(rule.NamespaceUID))
	}
	return accesscontrol.EvalAll(evals...)
}

// getRulesQueryEvaluator constructs accesscontrol.Evaluator that checks all permissions to query data sources used by the provided rules
func (r *RuleService) getRulesQueryEvaluator(rules ...*models.AlertRule) accesscontrol.Evaluator {
	added := make(map[string]struct{}, 2)
	evals := make([]accesscontrol.Evaluator, 0, 2)
	for _, rule := range rules {
		for _, query := range rule.Data {
			if query.QueryType == expr.DatasourceType || query.DatasourceUID == expr.DatasourceUID || query.
				DatasourceUID == expr.OldDatasourceUID {
				continue
			}
			if _, ok := added[query.DatasourceUID]; ok {
				continue
			}
			evals = append(evals, accesscontrol.EvalPermission(datasources.ActionQuery, datasources.ScopeProvider.GetResourceScopeUID(query.DatasourceUID)))
			added[query.DatasourceUID] = struct{}{}
		}
	}
	if len(evals) == 1 {
		return evals[0]
	}
	return accesscontrol.EvalAll(evals...)
}

// CanReadAllRules returns true when user has access to all folders and can read rules in them.
func (r *RuleService) CanReadAllRules(ctx context.Context, user identity.Requester) (bool, error) {
	return r.HasAccess(ctx, user, accesscontrol.EvalAll(
		accesscontrol.EvalPermission(ruleRead, dashboards.ScopeFoldersProvider.GetResourceAllScope()),
		accesscontrol.EvalPermission(dashboards.ActionFoldersRead, dashboards.ScopeFoldersProvider.GetResourceAllScope()),
	))
}

// AuthorizeDatasourceAccessForRule checks that user has access to all data sources declared by the rule
func (r *RuleService) AuthorizeDatasourceAccessForRule(ctx context.Context, user identity.Requester, rule *models.AlertRule) error {
	ds := r.getRulesQueryEvaluator(rule)
	return r.HasAccessOrError(ctx, user, ds, func() string {
		suffix := ""
		if rule.UID != "" {
			suffix = fmt.Sprintf(" of the rule UID '%s'", rule.UID)
		}
		return fmt.Sprintf("access one or many data sources%s", suffix)

		import { css } from '@emotion/css';
import { ErrorInfo, useEffect } from 'react';
import { useLocation } from 'react-router-dom-v5-compat';

import { GrafanaTheme2, locationUtil, PageLayoutType } from '@grafana/data';
import { Button, ErrorWithStack, useStyles2 } from '@grafana/ui';

import { Page } from '../components/Page/Page';

interface Props {
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export function GrafanaRouteError({ error, errorInfo }: Props) {
  const location = useLocation();
  const isChunkLoadingError = error?.name === 'ChunkLoadError';
  const styles = useStyles2(getStyles);

  useEffect(() => {
    // Auto reload page 1 time if we have a chunk load error
    if (isChunkLoadingError && location.search.indexOf('chunkNotFound') === -1) {
      window.location.href = locationUtil.getUrlForPartial(location, { chunkNotFound: true });
    }
  }, [location, isChunkLoadingError]);

  // Would be good to know the page navId here but needs a pretty big refactoring

  return (
    <Page navId="error" layout={PageLayoutType.Canvas}>
      <div className={styles.container}>
        {isChunkLoadingError && (
          <div>
            <h2>Unable to find application file</h2>
            <br />
            <h2 className="page-heading">Grafana has likely been updated. Please try reloading the page.</h2>
            <br />
            <Button size="md" variant="secondary" icon="repeat" onClick={() => window.location.reload()}>
              Reload
            </Button>
            <ErrorWithStack title={'Error details'} error={error} errorInfo={errorInfo} />
          </div>
        )}
        {!isChunkLoadingError && (
          <ErrorWithStack title={'An unexpected error happened'} error={error} errorInfo={errorInfo} />
        )}
      </div>
    </Page>
  );
}

const getStyles = (theme: GrafanaTheme2) => ({
  container: css({
    width: '500px',
    margin: theme.spacing(8, 'auto'),
  }),
});
