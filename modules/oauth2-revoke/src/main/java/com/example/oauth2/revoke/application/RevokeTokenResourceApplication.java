package com.example.oauth2.revoke.application;

import java.util.Collections;
import java.util.Set;

import javax.ws.rs.*;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.liferay.oauth2.provider.model.OAuth2Authorization;
import com.liferay.oauth2.provider.service.OAuth2AuthorizationLocalServiceUtil;
import com.liferay.oauth2.provider.service.OAuth2AuthorizationService;
import com.liferay.portal.kernel.exception.PortalException;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.jaxrs.whiteboard.JaxrsWhiteboardConstants;

/**
 * @author TuyenNN
 */
@Component(
	property = {
		JaxrsWhiteboardConstants.JAX_RS_APPLICATION_BASE + "=/greetings",
		JaxrsWhiteboardConstants.JAX_RS_NAME + "=Greetings.Rest"
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
			@FormParam("token") String token,
			@FormParam("token_type_hint") String tokenTypeHint
	) {
		// Tìm authorization bằng access token
		OAuth2Authorization auth =
				OAuth2AuthorizationLocalServiceUtil.
						fetchOAuth2AuthorizationByAccessTokenContent(token);

		if (auth == null) {
			return Response
					.status(Response.Status.BAD_REQUEST)
					.entity(Collections.singletonMap("error", "invalid_token"))
					.build();
		}

		// Gọi service để thu hồi token
        try {
            _oAuth2AuthorizationService.revokeOAuth2Authorization(
                    auth.getOAuth2AuthorizationId()
            );
        } catch (PortalException e) {
            throw new RuntimeException(e);
        }

        return Response.ok().build();
	}

}