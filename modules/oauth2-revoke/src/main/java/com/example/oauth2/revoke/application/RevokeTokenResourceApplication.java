package com.example.oauth2.revoke.application;


import java.util.Collections;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import com.liferay.oauth2.provider.model.OAuth2Authorization;
import com.liferay.oauth2.provider.service.OAuth2AuthorizationLocalServiceUtil;
import com.liferay.oauth2.provider.service.OAuth2AuthorizationService;
import com.liferay.portal.kernel.cache.CacheRegistryUtil;
import com.liferay.portal.kernel.exception.PortalException;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.jaxrs.whiteboard.JaxrsWhiteboardConstants;

/**
 * @author TuyenNN
 */
@Component(
	property = {
		JaxrsWhiteboardConstants.JAX_RS_APPLICATION_BASE + "=/account-logout",
		JaxrsWhiteboardConstants.JAX_RS_NAME + "=RevokeTokenResource",
			// Ép dùng OAuth2 verifier, tắt BasicAuth
			"osgi.jaxrs.extension.select=(osgi.jaxrs.name=Liferay.OAuth2)",
			// Vô hiệu hóa scope checking
			"oauth2.scopechecker.type=none"
	},
	service = Application.class
)
@Path("/revoke")
public class RevokeTokenResourceApplication extends Application {

	public Set<Object> getSingletons() {
		return Collections.<Object>singleton(this);
	}

	@org.osgi.service.component.annotations.Reference
	private OAuth2AuthorizationService _oAuth2AuthorizationService;

	@POST
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public Response revoke(
			@Context HttpServletRequest request
	) {
		// Tìm authorization bằng access token
        try {
			String authHeader = request.getHeader("Authorization");
			if (authHeader == null || !authHeader.startsWith("Bearer ")) {
				return Response
						.status(Response.Status.UNAUTHORIZED)
						.entity(Collections.singletonMap("error", "missing_or_invalid_authorization_header"))
						.build();
			}

			// Bóc token ra (bỏ chữ "Bearer ")
			String bearerToken = authHeader.substring("Bearer ".length());
			OAuth2Authorization auth =
					OAuth2AuthorizationLocalServiceUtil.
							fetchOAuth2AuthorizationByAccessTokenContent(bearerToken);

			if (auth == null) {
				return Response
						.status(Response.Status.BAD_REQUEST)
						.entity(Collections.singletonMap("error", "invalid_token"))
						.build();
			}
            _oAuth2AuthorizationService.revokeOAuth2Authorization(
                    auth.getOAuth2AuthorizationId()
            );
			CacheRegistryUtil.clear();

        } catch (PortalException e) {
            throw new RuntimeException(e);
        }

        return Response.status(Response.Status.OK).entity(Collections.singletonMap("success", "Logout successfully")).build();
	}

}