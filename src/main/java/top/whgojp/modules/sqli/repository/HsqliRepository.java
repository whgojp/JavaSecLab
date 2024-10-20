//package top.whgojp.modules.sqli.repository;
//
//import org.apache.ibatis.annotations.Param;
//import org.springframework.data.domain.Example;
//import org.springframework.data.domain.Page;
//import org.springframework.data.domain.Pageable;
//import org.springframework.data.domain.Sort;
//import org.springframework.data.jpa.repository.JpaRepository;
//import org.springframework.data.jpa.repository.Query;
//import org.springframework.data.repository.query.FluentQuery;
//import org.springframework.stereotype.Repository;
//import top.whgojp.modules.sqli.entity.Hsqli;
//
//import java.util.List;
//import java.util.Optional;
//import java.util.function.Function;
//
///**
// * @description <功能描述>
// * @author: whgojp
// * @email: whgojp@foxmail.com
// * @Date: 2024/8/5 18:09
// */
//@Repository
//public class HsqliRepository extends JpaRepository<Hsqli, Long> {
//
//    @Query("select t from sqli t where t.name like :name")
//    public List<Hsqli> findUserByName(@Param("name") String name) {
//        return null;
//    }
//
//    @Override
//    public List<Hsqli> findAll() {
//        return null;
//    }
//
//    @Override
//    public List<Hsqli> findAll(Sort sort) {
//        return null;
//    }
//
//    @Override
//    public Page<Hsqli> findAll(Pageable pageable) {
//        return null;
//    }
//
//    @Override
//    public List<Hsqli> findAllById(Iterable<Long> longs) {
//        return null;
//    }
//
//    @Override
//    public long count() {
//        return 0;
//    }
//
//    @Override
//    public void deleteById(Long aLong) {
//
//    }
//
//    @Override
//    public void delete(Hsqli entity) {
//
//    }
//
//    @Override
//    public void deleteAllById(Iterable<? extends Long> longs) {
//
//    }
//
//    @Override
//    public void deleteAll(Iterable<? extends Hsqli> entities) {
//
//    }
//
//    @Override
//    public void deleteAll() {
//
//    }
//
//    @Override
//    public <S extends Hsqli> S save(S entity) {
//        return null;
//    }
//
//    @Override
//    public <S extends Hsqli> List<S> saveAll(Iterable<S> entities) {
//        return null;
//    }
//
//    @Override
//    public Optional<Hsqli> findById(Long aLong) {
//        return Optional.empty();
//    }
//
//    @Override
//    public boolean existsById(Long aLong) {
//        return false;
//    }
//
//    @Override
//    public void flush() {
//
//    }
//
//    @Override
//    public <S extends Hsqli> S saveAndFlush(S entity) {
//        return null;
//    }
//
//    @Override
//    public <S extends Hsqli> List<S> saveAllAndFlush(Iterable<S> entities) {
//        return null;
//    }
//
//    @Override
//    public void deleteAllInBatch(Iterable<Hsqli> entities) {
//
//    }
//
//    @Override
//    public void deleteAllByIdInBatch(Iterable<Long> longs) {
//
//    }
//
//    @Override
//    public void deleteAllInBatch() {
//
//    }
//
//    @Override
//    public Hsqli getOne(Long aLong) {
//        return null;
//    }
//
//    @Override
//    public Hsqli getById(Long aLong) {
//        return null;
//    }
//
//    @Override
//    public Hsqli getReferenceById(Long aLong) {
//        return null;
//    }
//
//    @Override
//    public <S extends Hsqli> Optional<S> findOne(Example<S> example) {
//        return Optional.empty();
//    }
//
//    @Override
//    public <S extends Hsqli> List<S> findAll(Example<S> example) {
//        return null;
//    }
//
//    @Override
//    public <S extends Hsqli> List<S> findAll(Example<S> example, Sort sort) {
//        return null;
//    }
//
//    @Override
//    public <S extends Hsqli> Page<S> findAll(Example<S> example, Pageable pageable) {
//        return null;
//    }
//
//    @Override
//    public <S extends Hsqli> long count(Example<S> example) {
//        return 0;
//    }
//
//    @Override
//    public <S extends Hsqli> boolean exists(Example<S> example) {
//        return false;
//    }
//
//    @Override
//    public <S extends Hsqli, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) {
//        return null;
//    }
//}
