package top.whgojp.common.base;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import top.whgojp.common.utils.MPPageConvert;

/**
 * Controller公共组件
 *
 * @author whgojp
 * @email whgojp@foxmail.com
 * @date 2016年11月9日 下午9:42:26
 */

public abstract class AbstractController {

	@Autowired
	protected MPPageConvert mpPageConvert;

	@Autowired
	public ObjectMapper objectMapper;
}
