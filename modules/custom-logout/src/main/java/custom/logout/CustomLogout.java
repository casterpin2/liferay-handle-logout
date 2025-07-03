package custom.logout;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.liferay.oauth2.provider.model.OAuth2Authorization;
import com.liferay.oauth2.provider.service.OAuth2AuthorizationLocalServiceUtil;
import com.liferay.portal.kernel.dao.orm.QueryUtil;
import com.liferay.portal.kernel.events.ActionException;
import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.util.OrderByComparator;
import com.liferay.portal.kernel.util.OrderByComparatorFactoryUtil;
import org.osgi.service.component.annotations.Component;
import com.liferay.portal.kernel.events.Action;
import com.liferay.portal.kernel.events.LifecycleAction;
import com.liferay.portal.kernel.events.LifecycleEvent;

import java.util.List;

/**
 * @author TuyenNN
 */
@Component(
		immediate = true,
		property = "key=logout.events.post",
		service = LifecycleAction.class
)
public class CustomLogout implements LifecycleAction {

	@Override
	public void processLifecycleEvent(LifecycleEvent lifecycleEvent) throws ActionException {
		String userId = lifecycleEvent.getRequest().getRemoteUser();
		System.out.println("User đã logout: " + userId);
		long id = Long.parseLong(userId);
		OrderByComparator<OAuth2Authorization> comparator =
				OrderByComparatorFactoryUtil.create(
						OAuth2Authorization.class.getName(),  // the model class name
						"userId",          // the column to sort by
						/* ascending */ false
				);

		List<OAuth2Authorization> authorizations =
				OAuth2AuthorizationLocalServiceUtil.getUserOAuth2Authorizations(
						id , QueryUtil.ALL_POS, QueryUtil.ALL_POS,null);
		for (OAuth2Authorization auth : authorizations) {

			// hoặc nếu là custom column: auth.getRemoteHost()

            try {
                OAuth2AuthorizationLocalServiceUtil.deleteOAuth2Authorization(auth.getOAuth2AuthorizationId());
            } catch (PortalException e) {
                throw new RuntimeException(e);
            }
        }
		System.out.println("User đã logout: " + authorizations.size());
	}
}